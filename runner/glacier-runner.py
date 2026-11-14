#!/usr/bin/env python3
"""Narrow host-side runner for Synology Glacier Backup Manager.

This process intentionally accepts only mapping IDs and a run mode from the queue.
All paths, destinations and mandatory safety flags are rebuilt from validated config.
"""
from __future__ import annotations

import argparse
import ctypes
import fnmatch
import fcntl
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BUCKET = "example-archive-bucket"
REMOTE = "aws-archive"
RCLONE_CONFIG = "/volume1/@rclone/rclone.conf"
BUILTINS = ["**/@eaDir/**", "**/#recycle/**", "**/@Recycle/**", "**/.snapshot/**", "**/#snapshot/**", "**/.DS_Store", "**/Thumbs.db"]
REDACTIONS = [
    re.compile(r"(?i)(access[_ -]?key|secret|token|authorization)(\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(X-Amz-(?:Credential|Signature|Security-Token)=)[^&\s]+"),
]
STOP = False
RESTART = False
RUNNER_STATE = "idle"
RUNNER_PROGRESS = {}
CHANGE_INDEX = None
BILLING_CREDENTIALS = ""
BILLING_SERVICES = ["Amazon Simple Storage Service", "Amazon Glacier"]


class JobCancelled(Exception):
    pass
PERFORMANCE_DEFAULTS = {
    "scan_batch_entries": 100, "scan_pause_ms": 50,
    "transfers": 1, "checkers": 1, "bandwidth_mib": 0,
    "s3_requests_per_second": 8,
    "temperature_pause_c": 65, "temperature_resume_c": 60,
    "rclone_cpu_cores": 1,
}
PERFORMANCE_LIMITS = {
    "scan_batch_entries": (10, 1000), "scan_pause_ms": (10, 5000),
    "transfers": (1, 4), "checkers": (1, 8), "bandwidth_mib": (0, 10000),
    "s3_requests_per_second": (0, 20),
    "temperature_pause_c": (45, 90), "temperature_resume_c": (40, 85),
    "rclone_cpu_cores": (1, 4),
}


def iso(): return datetime.now(timezone.utc).isoformat()


def redact(text: str) -> str:
    for pattern in REDACTIONS:
        text = pattern.sub(r"\1\2[REDACTED]" if pattern.groups >= 2 else r"\1[REDACTED]", text)
    return text.replace("\x00", "")[:500_000]


PROTECTED_PATHS = ["/volume1/docker/synology-glacier-backup-manager"]


def validate_source(path: str) -> str:
    """Normalise first, then validate. Must stay equivalent to app.core.validate_source."""
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("Unsafe source path")
    value = os.path.normpath(path)
    if not re.fullmatch(r"/volume[0-9]+(?:/.*)?", value):
        raise ValueError("Unsafe source path")
    parts = value.split("/")[2:]
    if not parts or parts[0].startswith(("@", "#")):
        raise ValueError("Unsafe source path")
    protected = [*PROTECTED_PATHS, os.path.dirname(os.path.normpath(RCLONE_CONFIG))]
    if any(value == p or value.startswith(p.rstrip("/") + "/") for p in protected):
        raise ValueError("Source holds the manager's own data or credentials")
    return value


def validate_prefix(prefix: str) -> str:
    value = prefix.strip().strip("/")
    if not value or any(p in {"", ".", ".."} for p in value.split("/")):
        raise ValueError("Unsafe destination prefix")
    return value


def load_json(path):
    with Path(path).open(encoding="utf-8") as handle: return json.load(handle)


def performance_settings(config: dict) -> dict:
    supplied = config.get("performance", {})
    values = {}
    for key, default in PERFORMANCE_DEFAULTS.items():
        value = supplied.get(key, default)
        low, high = PERFORMANCE_LIMITS[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"Unsafe performance setting: {key}")
        values[key] = value
    if values["temperature_resume_c"] >= values["temperature_pause_c"]:
        raise ValueError("Resume temperature must be below pause temperature")
    return values


def constrain_rclone_process(cpu_cores: int):
    os.nice(19)
    if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        available = sorted(os.sched_getaffinity(0))
        os.sched_setaffinity(0, set(available[:cpu_cores]))


def build_command(mapping: dict, config: dict, dry_run: bool, file_list_path: str,
                  rclone_bin: str, combined_path: str | None = None) -> list[str]:
    source = validate_source(mapping["source"])
    destination = validate_prefix(mapping["destination"])
    limits = performance_settings(config)
    command = [rclone_bin, "copy", source, f"{REMOTE}:{BUCKET}/{destination}",
               "--config", RCLONE_CONFIG, "--no-traverse", "--s3-no-check-bucket",
               "--files-from0", file_list_path, "--use-json-log",
               "--transfers", str(limits["transfers"]), "--checkers", str(limits["checkers"]),
               "--buffer-size", "0", "--multi-thread-streams", "0",
               "--stats", "15s", "--stats-one-line", "--log-level", "INFO",
               "--retries", "1"]
    if combined_path:
        command.extend(["--combined", combined_path])
    if limits["s3_requests_per_second"]:
        command.extend(["--tpslimit", str(limits["s3_requests_per_second"]),
                        "--tpslimit-burst", str(limits["s3_requests_per_second"])])
    if limits["bandwidth_mib"]:
        command.extend(["--bwlimit", f'{limits["bandwidth_mib"]}M'])
    if dry_run: command.append("--dry-run")
    return command


def temperatures_c() -> list[float]:
    values = []
    paths = list(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    paths += list(Path("/sys/class/hwmon").glob("hwmon*/temp*_input"))
    for path in paths:
        try:
            value = float(path.read_text().strip())
            values.append(value / 1000 if value > 200 else value)
        except (OSError, ValueError):
            pass
    return values


def wait_for_safe_temperature(high: float, resume: float):
    readings = temperatures_c()
    if not readings or max(readings) < high:
        return
    logging.warning("Thermal pause at %.1f C", max(readings))
    while not STOP:
        time.sleep(15)
        readings = temperatures_c()
        if not readings or max(readings) <= resume:
            logging.info("Thermal pause ended")
            return


def excluded(relative: str, is_dir: bool, mapping: dict, config: dict) -> bool:
    parts = relative.split("/")
    if any(part in {"@eaDir", "#recycle", "@Recycle", ".snapshot", "#snapshot"} for part in parts):
        return True
    if not is_dir and parts[-1] in {".DS_Store", "Thumbs.db"}:
        return True
    for subtree in mapping.get("exclusions", []):
        subtree = subtree.strip("/")
        if relative == subtree or relative.startswith(subtree + "/"):
            return True
    candidate = relative + ("/" if is_dir else "")
    return any(fnmatch.fnmatch(candidate, pattern) or fnmatch.fnmatch(relative, pattern)
               for pattern in config.get("custom_exclusions", []))


def recent_file_list(mapping: dict, config: dict, on_directory=None, on_file=None, cancel_check=None) -> tuple[str, int]:
    """Walk locally at a controlled pace and return a NUL-separated rclone file list."""
    hours = int(config["schedule"]["max_age_hours"])
    if not 1 <= hours <= 720: raise ValueError("Unsafe max age")
    cutoff = time.time() - hours * 3600
    limits = performance_settings(config)
    batch = limits["scan_batch_entries"]
    delay = limits["scan_pause_ms"] / 1000
    thermal = (limits["temperature_pause_c"], limits["temperature_resume_c"])
    handle = tempfile.NamedTemporaryFile("wb", prefix="glacier-files-", delete=False)
    count = seen = 0
    index_reason = RUNNER_PROGRESS.get("index_reason")
    RUNNER_PROGRESS.clear()
    RUNNER_PROGRESS.update({"source": mapping["source"], "entries_scanned": 0,
                            "candidate_files": 0, "temperature_c": None})
    if index_reason: RUNNER_PROGRESS["index_reason"] = index_reason
    stack = [(Path(validate_source(mapping["source"])), "")]
    try:
        while stack and not STOP:
            if cancel_check and cancel_check(): raise JobCancelled("Cancelled during local scan")
            directory, relative_dir = stack.pop()
            try:
                directory_activity_time = directory.stat().st_mtime
                directory_recent = directory_activity_time >= cutoff
            except OSError:
                directory_activity_time = 0
                directory_recent = False
            if on_directory:
                on_directory(str(directory), relative_dir)
            wait_for_safe_temperature(*thermal)
            try:
                entries = os.scandir(directory)
            except (PermissionError, FileNotFoundError, OSError) as exc:
                logging.warning("Skipping unreadable folder %s: %s", directory, exc)
                continue
            with entries:
                for entry in entries:
                    relative = f"{relative_dir}/{entry.name}".lstrip("/")
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not excluded(relative, True, mapping, config):
                                stack.append((Path(entry.path), relative))
                        elif entry.is_file(follow_symlinks=False) and not excluded(relative, False, mapping, config):
                            stat = entry.stat(follow_symlinks=False)
                            activity_time = max(stat.st_mtime, stat.st_ctime)
                            # A move into a directory updates the directory timestamp even
                            # when the file retains an old embedded modification date.
                            if activity_time >= cutoff or directory_recent:
                                handle.write(os.fsencode(relative) + b"\0")
                                count += 1
                                if on_file:
                                    on_file(relative, stat.st_mtime, stat.st_size,
                                            max(activity_time, directory_activity_time))
                    except (PermissionError, FileNotFoundError, OSError) as exc:
                        logging.warning("Skipping unreadable entry %s: %s", entry.path, exc)
                    seen += 1
                    if seen % batch == 0:
                        if cancel_check and cancel_check(): raise JobCancelled("Cancelled during local scan")
                        handle.flush()
                        readings = temperatures_c()
                        RUNNER_PROGRESS.update({"entries_scanned": seen, "candidate_files": count,
                                                "temperature_c": round(max(readings), 1) if readings else None})
                        wait_for_safe_temperature(*thermal)
                        time.sleep(delay)
        if STOP:
            raise InterruptedError("Runner stopped during local scan")
        handle.flush()
        readings = temperatures_c()
        RUNNER_PROGRESS.update({"entries_scanned": seen, "candidate_files": count,
                                "temperature_c": round(max(readings), 1) if readings else None})
        return handle.name, count
    except Exception:
        handle.close()
        os.unlink(handle.name)
        raise
    finally:
        handle.close()


def explicit_file_list(mapping: dict, config: dict, selected_relative: str, cancel_check=None) -> tuple[str, int]:
    """Build a file list for one administrator-selected file or folder."""
    cancel_check = cancel_check or (lambda: False)
    root = Path(validate_source(mapping["source"])).resolve()
    selected_relative = str(selected_relative or "").strip("/")
    if selected_relative and any(part in {"", ".", ".."} for part in selected_relative.split("/")):
        raise ValueError("Invalid Upload now selection")
    selected = (root / selected_relative).resolve()
    if selected != root and root not in selected.parents:
        raise ValueError("Upload now selection escapes its source mapping")
    if not selected.exists() or selected.is_symlink():
        raise ValueError("Upload now selection is unavailable")
    output = tempfile.NamedTemporaryFile("wb", prefix="glacier-upload-now-", delete=False)
    count = 0
    def add_file(path: Path):
        nonlocal count
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or excluded(relative, False, mapping, config): return
        output.write(relative.encode("utf-8", "surrogateescape") + b"\0"); count += 1
    try:
        if selected.is_file():
            add_file(selected)
        else:
            for directory, names, filenames in os.walk(selected):
                relative_dir = Path(directory).relative_to(root).as_posix()
                relative_dir = "" if relative_dir == "." else relative_dir
                names[:] = [name for name in names if not (Path(directory) / name).is_symlink()
                            and not excluded(f"{relative_dir}/{name}".strip("/"), True, mapping, config)]
                for filename in filenames: add_file(Path(directory) / filename)
                if cancel_check(): raise JobCancelled("Cancelled while preparing Upload now")
        output.flush(); os.fsync(output.fileno())
    except Exception:
        output.close(); Path(output.name).unlink(missing_ok=True); raise
    output.close()
    return output.name, count


CATCHUP_MAX_SECONDS = 30 * 86400   # longer than this away and the index is rebuilt from scratch
CATCHUP_MIN_SECONDS = 90           # shorter gaps are covered by the 120 s safety margin below
CATCHUP_MARGIN = 120


def index_action(last_seen: float, now: float) -> tuple[str, str]:
    """Decide how to treat the change index after the runner was away.

    Filesystem events are lost while the runner is down, so instead of trusting the
    index blindly (or rebuilding it with a full walk) the runner re-checks only the
    folders whose modification time moved since it was last seen.
    """
    gap = now - last_seen
    minutes = round(gap / 60)
    if gap <= CATCHUP_MIN_SECONDS:
        return "keep", f"runner was away {minutes} min"
    if gap <= CATCHUP_MAX_SECONDS:
        return "catchup", f"runner was away {minutes} min; checking folders changed since then"
    return "rebuild", f"runner was away {minutes} min, too long to catch up"


class ChangeIndex:
    """Persistent change journal backed by Linux inotify and SQLite."""
    EVENT = struct.Struct("iIII")
    IN_ATTRIB = 0x00000004
    IN_CLOSE_WRITE = 0x00000008
    IN_MOVED_TO = 0x00000080
    IN_CREATE = 0x00000100
    IN_DELETE_SELF = 0x00000400
    IN_MOVE_SELF = 0x00000800
    IN_Q_OVERFLOW = 0x00004000
    IN_ISDIR = 0x40000000
    WATCH_MASK = IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.lock = threading.RLock()
        self.db = sqlite3.connect(data_dir / "change-index.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS mappings (id TEXT PRIMARY KEY, signature TEXT NOT NULL, initialized INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS directories (mapping_id TEXT NOT NULL, path TEXT NOT NULL, relative TEXT NOT NULL, PRIMARY KEY(mapping_id,path))")
        self.db.execute("CREATE TABLE IF NOT EXISTS changes (mapping_id TEXT NOT NULL, relative TEXT NOT NULL, mtime REAL NOT NULL, size INTEGER NOT NULL, observed_at REAL, PRIMARY KEY(mapping_id,relative))")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(changes)")}
        if "observed_at" not in columns:
            self.db.execute("ALTER TABLE changes ADD COLUMN observed_at REAL")
        mapping_columns = {row[1] for row in self.db.execute("PRAGMA table_info(mappings)")}
        if "reconciled_at" not in mapping_columns:
            self.db.execute("ALTER TABLE mappings ADD COLUMN reconciled_at REAL")
        self.db.execute("UPDATE changes SET observed_at=? WHERE observed_at IS NULL", (time.time(),))
        self.catchup_since = None
        self.caught_up = set()
        try:
            previous = load_json(data_dir / "runner-status.json")
            last_seen = datetime.fromisoformat(previous["last_seen"]).timestamp()
            action, why = index_action(last_seen, time.time())
            if action == "catchup":
                self.catchup_since = last_seen - CATCHUP_MARGIN
                logging.info("Keeping the change index: %s", why)
            elif action == "rebuild":
                logging.warning("Change index will be rebuilt: %s", why)
                self.db.execute("UPDATE mappings SET initialized=0")
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            self.db.execute("UPDATE mappings SET initialized=0")
        self.db.commit()
        libc = ctypes.CDLL(None, use_errno=True)
        self._add_watch = libc.inotify_add_watch
        self._add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._add_watch.restype = ctypes.c_int
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify initialization failed")
        self.watches = {}
        self.unwatched = set()

    def signature(self, mapping: dict, config: dict) -> str:
        return json.dumps({"source": mapping["source"], "exclusions": mapping.get("exclusions", []),
                           "custom": config.get("custom_exclusions", [])}, sort_keys=True)

    def watch_directory(self, mapping_id: str, path: str, relative: str):
        wd = self._add_watch(self.fd, os.fsencode(path), self.WATCH_MASK)
        if wd < 0:
            error = ctypes.get_errno()
            logging.warning("Cannot watch %s: %s", path, os.strerror(error))
            self.unwatched.add(mapping_id)
            return
        context = (mapping_id, path, relative)
        contexts = self.watches.setdefault(wd, [])
        if context not in contexts: contexts.append(context)

    def restore_watches(self):
        with self.lock:
            rows = self.db.execute("SELECT mapping_id,path,relative FROM directories").fetchall()
        for mapping_id, path, relative in rows:
            if os.path.isdir(path):
                self.watch_directory(mapping_id, path, relative)

    def ensure_mapping(self, mapping: dict, config: dict, cancel_check=None) -> tuple[str, int]:
        mapping_id = mapping["id"]
        signature = self.signature(mapping, config)
        with self.lock:
            row = self.db.execute("SELECT signature,initialized,reconciled_at FROM mappings WHERE id=?", (mapping_id,)).fetchone()
        if not row:
            RUNNER_PROGRESS["index_reason"] = "first baseline"
            return self.baseline(mapping, config, signature, cancel_check)
        if row[0] != signature:
            RUNNER_PROGRESS["index_reason"] = "folder selection or exclusions changed"
            return self.baseline(mapping, config, signature, cancel_check)
        if not row[1]:
            RUNNER_PROGRESS["index_reason"] = "runner restarted or filesystem events were missed"
            return self.baseline(mapping, config, signature, cancel_check)
        if mapping_id in self.unwatched:
            RUNNER_PROGRESS["index_reason"] = "filesystem watch capacity was unavailable"
            return self.baseline(mapping, config, signature, cancel_check)
        days = config.get("schedule", {}).get("full_scan_days", 0)
        if days and row[2] and time.time() - row[2] > days * 86400 - 3600:
            RUNNER_PROGRESS["index_reason"] = f"scheduled full scan (every {days} day{'s' if days != 1 else ''})"
            return self.baseline(mapping, config, signature, cancel_check)
        if getattr(self, "catchup_since", None) is not None and mapping_id not in self.caught_up:
            RUNNER_PROGRESS["index_reason"] = "catching up on changes made while the runner was away"
            self.catch_up(mapping, config, self.catchup_since, cancel_check)
            self.caught_up.add(mapping_id)
        return self.candidates(mapping, config)

    def catch_up(self, mapping: dict, config: dict, since: float, cancel_check=None):
        """Walk folders only; read files solely in folders touched since the runner was last seen."""
        mapping_id = mapping["id"]
        limits = performance_settings(config)
        batch = limits["scan_batch_entries"]
        delay = limits["scan_pause_ms"] / 1000
        thermal = (limits["temperature_pause_c"], limits["temperature_resume_c"])
        directories, changes, seen, found = [], [], 0, 0
        RUNNER_PROGRESS.update({"source": mapping["source"], "entries_scanned": 0, "candidate_files": 0})
        stack = [(Path(validate_source(mapping["source"])), "")]
        while stack and not STOP:
            if cancel_check and cancel_check(): raise JobCancelled("Cancelled during catch-up scan")
            directory, relative_dir = stack.pop()
            try: touched = directory.stat().st_mtime >= since
            except OSError: touched = False
            directories.append((mapping_id, str(directory), relative_dir))
            self.watch_directory(mapping_id, str(directory), relative_dir)
            if len(directories) >= 500:
                self._store_directories(directories); directories.clear()
            wait_for_safe_temperature(*thermal)
            try: entries = os.scandir(directory)
            except OSError as exc:
                logging.warning("Skipping unreadable folder %s: %s", directory, exc); continue
            with entries:
                for entry in entries:
                    relative = f"{relative_dir}/{entry.name}".lstrip("/")
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not excluded(relative, True, mapping, config): stack.append((Path(entry.path), relative))
                        elif touched and entry.is_file(follow_symlinks=False) and not excluded(relative, False, mapping, config):
                            stat = entry.stat(follow_symlinks=False)
                            if max(stat.st_mtime, stat.st_ctime) >= since:
                                changes.append((mapping_id, relative, stat.st_mtime, stat.st_size, time.time())); found += 1
                                if len(changes) >= 500: self._store_changes(changes); changes.clear()
                    except OSError as exc:
                        logging.warning("Skipping unreadable entry %s: %s", entry.path, exc)
                    seen += 1
                    if seen % batch == 0:
                        RUNNER_PROGRESS.update({"entries_scanned": seen, "candidate_files": found})
                        time.sleep(delay)
        if STOP: raise InterruptedError("Runner stopped during catch-up scan")
        self._store_directories(directories); self._store_changes(changes)
        logging.info("Catch-up for %s: %d folders' entries read, %d changed files found", mapping["source"], seen, found)

    def baseline(self, mapping: dict, config: dict, signature: str, cancel_check=None) -> tuple[str, int]:
        mapping_id = mapping["id"]
        with self.lock:
            self.db.execute("DELETE FROM directories WHERE mapping_id=?", (mapping_id,))
            self.db.execute("INSERT OR REPLACE INTO mappings(id,signature,initialized,reconciled_at) VALUES(?,?,0,NULL)", (mapping_id, signature))
            self.db.commit()
        directories = []
        changes = []
        def directory(path, relative):
            directories.append((mapping_id, path, relative))
            self.watch_directory(mapping_id, path, relative)
            if len(directories) >= 500:
                self._store_directories(directories); directories.clear()
        def changed(relative, mtime, size, observed_at):
            changes.append((mapping_id, relative, mtime, size, observed_at))
            if len(changes) >= 500:
                self._store_changes(changes); changes.clear()
        filename, count = recent_file_list(mapping, config, directory, changed, cancel_check)
        self._store_directories(directories); self._store_changes(changes)
        with self.lock:
            self.db.execute("UPDATE mappings SET initialized=1,reconciled_at=? WHERE id=?", (time.time(), mapping_id)); self.db.commit()
        return filename, count

    def _store_directories(self, rows):
        if not rows: return
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO directories(mapping_id,path,relative) VALUES(?,?,?)", rows); self.db.commit()

    def _store_changes(self, rows):
        if not rows: return
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO changes(mapping_id,relative,mtime,size,observed_at) VALUES(?,?,?,?,?)", rows); self.db.commit()

    def candidates(self, mapping: dict, config: dict) -> tuple[str, int]:
        # Every change not yet confirmed uploaded stays a candidate, regardless of the
        # modification window. The window only governs what the first baseline scan
        # indexes; otherwise a NAS outage or failing jobs longer than the window would
        # silently drop never-uploaded files from the backup.
        stale = time.time() - 31 * 86400
        with self.lock:
            expired = self.db.execute("SELECT COUNT(*) FROM changes WHERE COALESCE(observed_at,mtime)<?", (stale,)).fetchone()[0]
            if expired:
                logging.error("Discarding %d un-uploaded change records older than 31 days", expired)
            self.db.execute("DELETE FROM changes WHERE COALESCE(observed_at,mtime)<?", (stale,)); self.db.commit()
            rows = self.db.execute("SELECT relative,mtime,size FROM changes WHERE mapping_id=? ORDER BY relative", (mapping["id"],)).fetchall()
            oldest = self.db.execute("SELECT MIN(COALESCE(observed_at,mtime)) FROM changes WHERE mapping_id=?", (mapping["id"],)).fetchone()[0]
        window = int(config["schedule"]["max_age_hours"]) * 3600
        if oldest and time.time() - oldest > window:
            logging.warning("Un-uploaded changes older than the %d hour window are still queued for %s", window // 3600, mapping["source"])
        handle = tempfile.NamedTemporaryFile("wb", prefix="glacier-indexed-files-", delete=False)
        count = 0
        try:
            for relative, _, _ in rows:
                path = Path(mapping["source"]) / relative
                if path.is_file() and not excluded(relative, False, mapping, config):
                    handle.write(os.fsencode(relative) + b"\0"); count += 1
            handle.close()
            RUNNER_PROGRESS.clear(); RUNNER_PROGRESS.update({"source": mapping["source"], "indexed_changes": count})
            return handle.name, count
        except Exception:
            handle.close(); os.unlink(handle.name); raise

    def complete_paths(self, mapping_id: str, paths: list[str]):
        rows = [(mapping_id, path) for path in paths]
        with self.lock:
            self.db.executemany("DELETE FROM changes WHERE mapping_id=? AND relative=?", rows); self.db.commit()

    def complete(self, mapping_id: str, file_list: str):
        raw = Path(file_list).read_bytes().split(b"\0")
        self.complete_paths(mapping_id, [os.fsdecode(item) for item in raw if item])

    def mapping_for(self, mapping_id: str):
        try:
            config = load_json(self.data_dir / "config.json")
            mapping = next((m for m in config.get("mappings", []) if m.get("id") == mapping_id and m.get("enabled", True)), None)
            return mapping, config
        except Exception:
            return None, None

    def record_path(self, mapping_id: str, full_path: str, relative: str):
        mapping, config = self.mapping_for(mapping_id)
        if not mapping or excluded(relative, os.path.isdir(full_path), mapping, config): return
        if os.path.isdir(full_path):
            self.watch_directory(mapping_id, full_path, relative)
            self._store_directories([(mapping_id, full_path, relative)])
            try:
                for entry in os.scandir(full_path):
                    child = f"{relative}/{entry.name}".strip("/")
                    self.record_path(mapping_id, entry.path, child)
            except OSError: pass
        elif os.path.isfile(full_path):
            try:
                stat = os.stat(full_path, follow_symlinks=False)
                self._store_changes([(mapping_id, relative, stat.st_mtime, stat.st_size, time.time())])
            except OSError: pass

    def watch(self):
        self.restore_watches()
        while not STOP:
            try:
                payload = os.read(self.fd, 1024 * 128)
            except BlockingIOError:
                time.sleep(0.5); continue
            except OSError:
                time.sleep(2); continue
            offset = 0
            while offset + self.EVENT.size <= len(payload):
                wd, mask, _, length = self.EVENT.unpack_from(payload, offset); offset += self.EVENT.size
                name = payload[offset:offset+length].split(b"\0", 1)[0]; offset += length
                if mask & self.IN_Q_OVERFLOW:
                    logging.error("Filesystem change queue overflowed; mappings require reconciliation")
                    with self.lock: self.db.execute("UPDATE mappings SET initialized=0"); self.db.commit()
                    continue
                contexts = self.watches.get(wd, [])
                if not contexts or not name: continue
                for mapping_id, directory, relative_dir in contexts:
                    filename = os.fsdecode(name); full_path = os.path.join(directory, filename)
                    relative = f"{relative_dir}/{filename}".strip("/")
                    if mask & (self.IN_ATTRIB | self.IN_CLOSE_WRITE | self.IN_MOVED_TO | self.IN_CREATE):
                        self.record_path(mapping_id, full_path, relative)


def parse_output(text: str, dry_run: bool = False) -> tuple[int, int]:
    files = total_bytes = 0
    for line in text.splitlines():
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        message = str(item.get("msg", "")).lower()
        copied = message.startswith("copied")
        planned = dry_run and "dry-run" in message and ("skip" in message or "copy" in message)
        if copied or planned:
            files += 1
            total_bytes += max(0, int(item.get("size", 0) or 0))
    return files, total_bytes


def candidate_details(mapping: dict, file_list: str) -> tuple[dict[str, int], list[str]]:
    """Validate the exact local paths handed to rclone and retain their sizes."""
    source = Path(validate_source(mapping["source"]))
    sizes = {}
    missing = []
    for item in Path(file_list).read_bytes().split(b"\0"):
        if not item: continue
        relative = os.fsdecode(item)
        try:
            target = source / relative
            stat = target.stat()
            if not target.is_file(): raise FileNotFoundError(relative)
            sizes[relative] = max(0, stat.st_size)
        except OSError:
            missing.append(relative)
    return sizes, missing


def parse_combined_report(text: str) -> dict[str, str]:
    """Return rclone's explicit per-path decision from its combined report."""
    outcomes = {}
    for line in text.splitlines():
        if len(line) >= 3 and line[0] in "=-+*!" and line[1] == " ":
            outcomes[line[2:]] = line[0]
    return outcomes


def readable_outcome_report(candidates: dict[str, int], outcomes: dict[str, str]) -> str:
    labels = {
        "=": "already present and identical",
        "+": "uploaded (was missing from destination)",
        "*": "uploaded (destination copy differed)",
        "-": "missing from local source",
        "!": "could not be checked",
    }
    lines = ["Candidate outcomes:"]
    for relative in sorted(candidates):
        symbol = outcomes.get(relative)
        label = labels.get(symbol, "UNACCOUNTED FOR; retained for retry")
        lines.append(f"- {relative} ({candidates[relative]} B): {label}")
    return "\n".join(lines)


def update_live_transfer_stats(text: str) -> None:
    latest = None
    for line in text.splitlines():
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        if item.get("stats"): latest = item["stats"]
    if not latest: return
    transferred = max(0, int(latest.get("bytes", 0) or 0))
    total = max(0, int(latest.get("totalBytes", 0) or 0))
    completed = max(0, int(latest.get("transfers", 0) or 0))
    total_files = max(0, int(latest.get("totalTransfers", 0) or 0))
    percentage = (transferred / total * 100) if total else ((completed / total_files * 100) if total_files else 0)
    RUNNER_PROGRESS.update({
        "bytes_transferred": transferred, "total_bytes": total,
        "files_transferred": completed, "total_files": total_files,
        "speed_bps": max(0, float(latest.get("speed", 0) or 0)),
        "eta_seconds": max(0, float(latest.get("eta", 0) or 0)),
        "percentage": min(100, round(percentage, 1)),
    })


def write_result(data_dir: Path, value: dict):
    target = data_dir / "jobs/results" / f"{value['id']}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=target.name + ".")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2); handle.flush(); os.fsync(handle.fileno())
    os.replace(tmp, target)


def write_status(data_dir: Path, rclone_bin: str, state: str = "idle"):
    target = data_dir / "runner-status.json"
    status = {"last_seen": iso(), "state": state, "rclone": rclone_bin,
              "billing_configured": bool(BILLING_CREDENTIALS) and os.path.isfile(BILLING_CREDENTIALS),
              "capabilities": ["rclone-config-v1", "folder-archive-v1", "folder-archive-v2", "folder-archive-v3", "folder-archive-v4", "s3-browser-v1", "upload-now-v1", "s3-size-v1", "billing-v1"], **RUNNER_PROGRESS}
    readings = temperatures_c()
    status["temperature_c"] = round(max(readings), 1) if readings else None
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix="runner-status.")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(status, handle)
        handle.flush(); os.fsync(handle.fileno())
    os.replace(tmp, target)


def heartbeat(data_dir: Path, rclone_bin: str):
    while not STOP:
        try: write_status(data_dir, rclone_bin, RUNNER_STATE)
        except OSError: pass
        time.sleep(2)


def archive_name(source: str, archive_format: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._ -]+", "_", Path(source).name).strip(" ._") or "folder"
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d")
    return f"{base}_{stamp}.{archive_format}"


def archive_destination(job: dict, source: str) -> str:
    mode = job.get("destination_mode", "custom")
    if mode in {"source", "parent"}:
        parts = Path(validate_source(source)).parts
        hierarchy = parts[2:] if mode == "source" else parts[2:-1]
        return validate_prefix("/".join(hierarchy)) if hierarchy else ""
    return validate_prefix(job.get("destination", ""))


def archive_source(source: str, target: Path, archive_format: str, config: dict, cancel_check,
                   exclusions: list[str] | None = None) -> tuple[int, int]:
    """Create one folder archive locally while publishing bounded progress."""
    root = Path(validate_source(source))
    if not root.is_dir(): raise ValueError(f"Archive source is unavailable: {source}")
    exclusions = [value.strip("/") for value in (exclusions or [])]
    def is_excluded(relative: str) -> bool:
        return any(relative == value or relative.startswith(value + "/") for value in exclusions)
    total_bytes = entries = 0
    for directory, names, filenames in os.walk(root):
        relative_dir = os.path.relpath(directory, root)
        relative_dir = "" if relative_dir == "." else relative_dir
        names[:] = [name for name in names
                    if name not in {"@eaDir", "#recycle", "@Recycle", ".snapshot", "#snapshot"}
                    and not is_excluded(f"{relative_dir}/{name}".strip("/"))]
        for filename in filenames:
            if filename in {".DS_Store", "Thumbs.db"}: continue
            relative = f"{relative_dir}/{filename}".strip("/")
            if is_excluded(relative): continue
            try: total_bytes += max(0, (Path(directory) / filename).stat().st_size); entries += 1
            except OSError: pass
        if cancel_check(): raise JobCancelled("Cancelled while measuring archive")
    required = total_bytes + entries * 1024 + 64 * 1024 * 1024
    if shutil.disk_usage(target.parent).free < required:
        raise ValueError(f"Not enough temporary space to archive {root.name}; approximately {required} bytes are required")
    mode = "w:gz" if archive_format == "tar.gz" else "w"
    processed = seen = 0
    limits = performance_settings(config)
    def filter_member(member):
        nonlocal processed, seen
        relative_parts = Path(member.name).parts[1:]
        relative = "/".join(relative_parts)
        if relative and is_excluded(relative): return None
        if any(part in {"@eaDir", "#recycle", "@Recycle", ".snapshot", "#snapshot"} for part in relative_parts):
            return None
        if relative_parts and relative_parts[-1] in {".DS_Store", "Thumbs.db"}: return None
        if member.isfile(): processed += max(0, member.size); seen += 1
        RUNNER_PROGRESS.update({"source": source, "archive_entries": seen,
                                "bytes_processed": processed, "total_bytes": total_bytes,
                                "percentage": min(100, round(processed / total_bytes * 100, 1)) if total_bytes else 100})
        if cancel_check(): raise JobCancelled("Cancelled while creating archive")
        if seen and seen % limits["scan_batch_entries"] == 0:
            wait_for_safe_temperature(limits["temperature_pause_c"], limits["temperature_resume_c"])
            time.sleep(limits["scan_pause_ms"] / 1000)
        return member
    with tarfile.open(target, mode, dereference=False) as archive:
        archive.add(root, arcname=root.name, recursive=True, filter=filter_member)
    return entries, total_bytes


def execute_archive_job(job: dict, data_dir: Path, rclone_bin: str, config: dict):
    global RUNNER_STATE
    if job.get("archive_format") not in {"tar", "tar.gz"}:
        raise ValueError("Invalid archive format")
    if not isinstance(job.get("sources"), list) or not 1 <= len(job["sources"]) <= 20:
        raise ValueError("Invalid archive source selection")
    if job.get("destination_mode", "custom") not in {"source", "parent", "custom"}:
        raise ValueError("Invalid archive destination mode")
    if job.get("destination_mode", "custom") == "custom":
        validate_prefix(job.get("destination", ""))
    for selection in job["sources"]:
        if not isinstance(selection, dict): raise ValueError("Invalid archive source selection")
        validate_source(selection.get("source", ""))
        for exclusion in selection.get("exclusions", []):
            if not exclusion or any(part in {"", ".", ".."} for part in str(exclusion).strip("/").split("/")):
                raise ValueError("Invalid archive exclusion")
    cancel_marker = data_dir / "jobs/cancel" / job["id"]
    cancel_requested = cancel_marker.exists
    started = time.monotonic(); started_at = iso(); logs=[]; uploaded=uploaded_bytes=0
    status="success"; error=""; target=None; summary=[]; work = data_dir / "archive-work"; work.mkdir(parents=True, exist_ok=True)
    used_names = set()
    try:
        for selection in job.get("sources", []):
            source = selection["source"]
            if cancel_requested(): raise JobCancelled("Cancelled before archive creation")
            name = archive_name(source, job["archive_format"])
            if name in used_names:
                stem, suffix = name.rsplit(".", 1); name = f"{stem}_{len(used_names)+1}.{suffix}"
            used_names.add(name)
            target = work / f"{job['id']}-{name}"
            RUNNER_STATE = "archiving"; RUNNER_PROGRESS.clear()
            logs.append(f"Creating {name} from {source}")
            entries, source_bytes = archive_source(source, target, job["archive_format"], config,
                                                   cancel_requested, selection.get("exclusions", []))
            archive_bytes = target.stat().st_size
            logs.append(f"Created {name}: {entries} files, {archive_bytes} bytes (source {source_bytes} bytes)")
            destination = archive_destination(job, source)
            remote_key = "/".join(value for value in (destination, name) if value)
            remote_path = f"{REMOTE}:{BUCKET}/{remote_key}"
            limits = performance_settings(config)
            command = [rclone_bin, "copyto", str(target), remote_path, "--config", RCLONE_CONFIG,
                       "--s3-no-check-bucket", "--immutable", "--use-json-log", "--stats", "5s",
                       "--stats-one-line", "--log-level", "INFO", "--transfers", "1", "--checkers", "1",
                       "--buffer-size", "0", "--multi-thread-streams", "0", "--retries", "1"]
            if limits["s3_requests_per_second"]:
                command.extend(["--tpslimit", str(limits["s3_requests_per_second"]),
                                "--tpslimit-burst", str(limits["s3_requests_per_second"])])
            if limits["bandwidth_mib"]: command.extend(["--bwlimit", f'{limits["bandwidth_mib"]}M'])
            RUNNER_STATE = "uploading"; RUNNER_PROGRESS.update({"files_to_check": len(job["sources"]), "archive_name": name})
            output = tempfile.NamedTemporaryFile("w+", prefix="glacier-archive-upload-", delete=False); output.close()
            try:
                with open(output.name, "w", encoding="utf-8") as stream, open(output.name, "r", encoding="utf-8") as reader:
                    environment = {**os.environ, "GOMAXPROCS": str(limits["rclone_cpu_cores"])}
                    proc = subprocess.Popen(command, text=True, stdout=stream, stderr=subprocess.STDOUT,
                                            env=environment, preexec_fn=lambda: constrain_rclone_process(limits["rclone_cpu_cores"]))
                    buffer = ""
                    while proc.poll() is None:
                        buffer += reader.read()
                        complete = buffer.rsplit("\n", 1)
                        if len(complete) == 2: update_live_transfer_stats(complete[0]); buffer = complete[1]
                        if cancel_requested():
                            proc.terminate()
                            try: proc.wait(timeout=10)
                            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                            raise JobCancelled("Cancelled during archive upload")
                        time.sleep(1)
                    buffer += reader.read(); update_live_transfer_stats(buffer)
                raw = Path(output.name).read_text(encoding="utf-8", errors="replace")
            finally:
                Path(output.name).unlink(missing_ok=True)
            logs.append(redact(raw))
            if proc.returncode:
                raise ValueError(f"Archive upload failed with rclone status {proc.returncode}; local archive retained at {target}")
            uploaded += 1; uploaded_bytes += archive_bytes
            target.unlink()
            logs.append(f"Uploaded and verified {remote_path}; temporary local archive removed")
            summary.append({"outcome":"archive_uploaded", "source":source, "name":name,
                            "destination":f"{destination}/{name}", "size":archive_bytes,
                            "entries":entries})
    except JobCancelled as exc:
        status="cancelled"; error=redact(str(exc)); logs.append(error)
        if target and target.exists(): logs.append(f"Incomplete local archive retained at {target}")
    except Exception as exc:
        status="failed"; error=redact(str(exc)); logs.append(error)
        if target and target.exists(): logs.append(f"Local archive retained at {target}")
    result={"id":job["id"],"mode":"archive","trigger":"manual","started_at":started_at,
            "finished_at":iso(),"status":status,"files":uploaded,"candidates":len(job.get("sources", [])),
            "bytes":uploaded_bytes,"duration":time.monotonic()-started,"error":error,"log":"\n".join(logs)}
    result["summary"] = json.dumps(summary, ensure_ascii=False)
    write_result(data_dir,result); cancel_marker.unlink(missing_ok=True); RUNNER_PROGRESS.clear(); RUNNER_STATE="idle"


def execute_job(path: Path, data_dir: Path, rclone_bin: str):
    global RUNNER_STATE, CHANGE_INDEX
    RUNNER_STATE = "working"
    job = load_json(path); config = load_json(data_dir / "config.json")
    cancel_marker = data_dir / "jobs/cancel" / job["id"]
    cancel_requested = cancel_marker.exists
    if config.get("safety", {}).get("paused", True):
        raise ValueError("Backup engine is paused for NAS safety")
    if config.get("remote") != REMOTE or config.get("bucket") != BUCKET or config.get("rclone_config") != RCLONE_CONFIG:
        raise ValueError("Fixed destination settings changed")
    if job.get("mode") == "archive":
        return execute_archive_job(job, data_dir, rclone_bin, config)
    mappings = {m["id"]: m for m in config.get("mappings", []) if m.get("enabled", True)}
    chosen = [mappings[mid] for mid in job.get("mapping_ids", []) if mid in mappings]
    if not chosen: raise ValueError("No valid enabled mappings")
    dry_run = job.get("mode") == "dry-run"
    if job.get("mode") not in {"dry-run", "backup", "upload-now"}: raise ValueError("Invalid mode")
    started = time.monotonic(); started_at = iso(); logs=[]; summary=[]; files=total_bytes=candidates=0; error=""; status="success"
    try:
        for mapping in chosen:
            file_list = combined_file = None
            try:
                RUNNER_STATE = "scanning"
                if job.get("mode") == "upload-now":
                    file_list, candidate_count = explicit_file_list(mapping, config, job.get("selected_path", ""), cancel_requested)
                else:
                    file_list, candidate_count = CHANGE_INDEX.ensure_mapping(mapping, config, cancel_requested)
                candidates += candidate_count
                logs.append(f"Mapping: {mapping['source']} -> {REMOTE}:{BUCKET}/{mapping['destination']}")
                if mapping.get("exclusions"): logs.append(f"Excluded subfolders: {', '.join(mapping['exclusions'])}")
                logs.append(f"Upload now selected {candidate_count} files" if job.get("mode") == "upload-now"
                            else f"Throttled local scan found {candidate_count} recent files")
                if not candidate_count:
                    continue
                candidate_sizes, missing_candidates = candidate_details(mapping, file_list)
                if missing_candidates:
                    logs.append("Local candidates disappeared before upload and were retained for retry:\n- " +
                                "\n- ".join(sorted(missing_candidates)))
                if not candidate_sizes:
                    continue
                RUNNER_STATE = "uploading"
                RUNNER_PROGRESS.update({"files_to_check": candidate_count})
                combined = tempfile.NamedTemporaryFile("w", prefix="glacier-outcomes-", delete=False)
                combined_file = combined.name; combined.close()
                command = build_command(mapping, config, dry_run, file_list, rclone_bin, combined_file)
                output = tempfile.NamedTemporaryFile("w+", prefix="glacier-rclone-", delete=False)
                output.close(); cancelled = False
                try:
                    with open(output.name, "w", encoding="utf-8") as stream, open(output.name, "r", encoding="utf-8") as live_reader:
                        limits = performance_settings(config)
                        environment = {**os.environ, "GOMAXPROCS": str(limits["rclone_cpu_cores"])}
                        proc = subprocess.Popen(command, text=True, stdout=stream, stderr=subprocess.STDOUT,
                                                env=environment,
                                                preexec_fn=lambda: constrain_rclone_process(limits["rclone_cpu_cores"]))
                        deadline = time.monotonic() + 24 * 3600
                        live_buffer = ""
                        while proc.poll() is None:
                            live_buffer += live_reader.read()
                            complete = live_buffer.rsplit("\n", 1)
                            if len(complete) == 2:
                                update_live_transfer_stats(complete[0]); live_buffer = complete[1]
                            if cancel_requested():
                                cancelled = True; proc.terminate()
                                try: proc.wait(timeout=10)
                                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                                break
                            if time.monotonic() >= deadline:
                                proc.kill(); proc.wait(); raise TimeoutError("rclone exceeded the 24 hour job limit")
                            time.sleep(1)
                        live_buffer += live_reader.read()
                        update_live_transfer_stats(live_buffer)
                    raw = Path(output.name).read_text(encoding="utf-8", errors="replace")
                finally:
                    try: os.unlink(output.name)
                    except OSError: pass
                clean = redact(raw); logs.append(clean)
                count, amount = parse_output(raw, dry_run)
                if cancelled: raise JobCancelled("Cancelled during rclone operation")
                if proc.returncode:
                    status="failed"; error=f"rclone exited with status {proc.returncode}"; break
                report = Path(combined_file).read_text(encoding="utf-8", errors="replace")
                outcomes = parse_combined_report(report)
                logs.append(readable_outcome_report(candidate_sizes, outcomes))
                outcome_names = {"=":"already_present", "+":"uploaded_new", "*":"uploaded_replaced",
                                 "-":"missing_local", "!":"failed"}
                for relative, size in candidate_sizes.items():
                    summary.append({"outcome":outcome_names.get(outcomes.get(relative), "unaccounted"),
                                    "source":mapping["source"], "path":relative,
                                    "destination":f"{mapping['destination'].rstrip('/')}/{relative}", "size":size})
                accounted = [relative for relative in candidate_sizes if outcomes.get(relative) in {"=", "+", "*"}]
                unexplained = [relative for relative in candidate_sizes if relative not in outcomes or outcomes.get(relative) == "!"]
                copied = [relative for relative in candidate_sizes if outcomes.get(relative) in {"+", "*"}]
                files += max(count, len(copied))
                total_bytes += max(amount, sum(candidate_sizes[relative] for relative in copied))
                if unexplained:
                    status = "failed"
                    error = f"rclone did not safely account for {len(unexplained)} candidate file(s); retained for retry"
                    logs.append(error)
                    break
                if not dry_run:
                    CHANGE_INDEX.complete_paths(mapping["id"], accounted)
            finally:
                if file_list:
                    try: os.unlink(file_list)
                    except OSError: pass
                if combined_file:
                    try: os.unlink(combined_file)
                    except OSError: pass
    except JobCancelled as exc:
        status="cancelled"; error=redact(str(exc)); logs.append(error)
    except Exception as exc:
        status="failed"; error=redact(str(exc)); logs.append(error)
    result={"id":job["id"],"mode":job["mode"],"trigger":job.get("trigger","manual"),"started_at":started_at,
            "finished_at":iso(),"status":status,"files":files,"candidates":candidates,
            "bytes":total_bytes,"duration":time.monotonic()-started,
            "error":error,"log":"\n".join(logs),"summary":json.dumps(summary, ensure_ascii=False)}
    write_result(data_dir,result)
    cancel_marker.unlink(missing_ok=True)
    RUNNER_PROGRESS.clear()
    RUNNER_STATE = "idle"


def run_once(data_dir: Path, rclone_bin: str) -> bool:
    global RUNNER_STATE
    pending=data_dir/"jobs/pending"; running=data_dir/"jobs/running"; running.mkdir(parents=True,exist_ok=True)
    try:
        if load_json(data_dir / "config.json").get("safety", {}).get("paused", True):
            RUNNER_STATE = "paused"
            return False
    except (OSError, ValueError, json.JSONDecodeError):
        RUNNER_STATE = "paused"
        return False
    if RUNNER_STATE == "paused":
        RUNNER_STATE = "idle"
        RUNNER_PROGRESS.clear()
    jobs=sorted(pending.glob("*.json"),key=lambda p:p.stat().st_mtime)
    if not jobs:return False
    path=jobs[0]; active=running/path.name; os.replace(path,active)
    try: execute_job(active,data_dir,rclone_bin)
    except Exception as exc:
        job=load_json(active); write_result(data_dir,{"id":job.get("id",active.stem),"mode":job.get("mode","unknown"),"trigger":job.get("trigger","manual"),"started_at":iso(),"finished_at":iso(),"status":"failed","files":0,"bytes":0,"duration":0,"error":redact(str(exc)),"log":redact(str(exc))})
    finally:
        RUNNER_STATE = "idle"
        active.unlink(missing_ok=True)
    return True


def recover_interrupted_jobs(data_dir: Path):
    running = data_dir / "jobs/running"
    for active in running.glob("*.json"):
        try:
            job = load_json(active)
            write_result(data_dir, {"id": job.get("id", active.stem), "mode": job.get("mode", "unknown"),
                "trigger": job.get("trigger", "manual"), "started_at": job.get("created_at", iso()),
                "finished_at": iso(), "status": "interrupted", "files": 0, "bytes": 0, "duration": 0,
                "error": "Runner stopped before the job completed", "log": "Runner stopped before the job completed"})
            active.unlink(missing_ok=True)
        except Exception:
            logging.exception("Could not recover interrupted job %s", active.name)


def inspect_rclone_remote(rclone_bin: str) -> dict:
    proc = subprocess.run([rclone_bin, "config", "redacted", REMOTE, "--config", RCLONE_CONFIG],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if proc.returncode:
        return {"configured": False, "remote": REMOTE, "config_path": RCLONE_CONFIG,
                "error": redact(proc.stdout.strip())}
    allowed = {"type", "provider", "env_auth", "region", "endpoint", "profile"}
    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = [part.strip() for part in line.split("=", 1)]
            if key in allowed: values[key] = value
    return {"configured": True, "remote": REMOTE, "config_path": RCLONE_CONFIG, **values}


def configure_rclone_remote(request: dict, rclone_bin: str):
    access_key = str(request.get("access_key_id", "")).strip()
    secret_key = str(request.get("secret_access_key", ""))
    auth_mode = request.get("auth_mode", "keys")
    if auth_mode not in {"keys", "environment"}: raise ValueError("Invalid authentication mode")
    if auth_mode == "keys":
        if not re.fullmatch(r"[A-Za-z0-9]{16,128}", access_key): raise ValueError("Invalid AWS access key ID")
        if not 20 <= len(secret_key) <= 256 or any(ch in secret_key for ch in "\r\n\x00"):
            raise ValueError("Invalid AWS secret access key")
        obscure = subprocess.run([rclone_bin, "obscure", "-"], input=secret_key, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if obscure.returncode: raise ValueError("rclone could not obscure the secret key")
        credential_lines = f"env_auth = false\naccess_key_id = {access_key}\nsecret_access_key = {obscure.stdout.strip()}\n"
    else:
        credential_lines = "env_auth = true\n"
    config_path = Path(RCLONE_CONFIG)
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if existing.startswith("RCLONE_ENCRYPT_V"):
        raise ValueError("Encrypted rclone configurations must be managed through the terminal")
    section = (f"[{REMOTE}]\ntype = s3\nprovider = AWS\n{credential_lines}"
               "region = us-west-2\nacl = private\nstorage_class =\n")
    pattern = re.compile(rf"(?ms)^\[{re.escape(REMOTE)}\]\s*\n.*?(?=^\[|\Z)")
    updated = pattern.sub(section + "\n", existing) if pattern.search(existing) else existing.rstrip() + "\n\n" + section
    fd, temporary = tempfile.mkstemp(prefix="rclone.conf.", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temporary, 0o600); os.replace(temporary, config_path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def browse_s3(request: dict, rclone_bin: str) -> dict:
    """List one explicitly requested level of the fixed archive bucket."""
    prefix = str(request.get("prefix", "")).strip().strip("/")
    if "\x00" in prefix or any(part in {"", ".", ".."} for part in prefix.split("/") if prefix):
        raise ValueError("Invalid S3 location")
    remote_path = f"{REMOTE}:{BUCKET}" + (f"/{prefix}" if prefix else "")
    proc = subprocess.run([rclone_bin, "lsjson", remote_path, "--config", RCLONE_CONFIG,
                           "--max-depth", "1", "--no-mimetype"], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if proc.returncode:
        raise ValueError(f"S3 browser failed: {redact(proc.stdout.strip())}")
    raw = json.loads(proc.stdout or "[]")
    entries = [{"name": str(item.get("Name", "")), "is_dir": bool(item.get("IsDir")),
                "size": max(0, int(item.get("Size", 0) or 0)), "modified": item.get("ModTime")}
               for item in raw if item.get("Name")]
    entries.sort(key=lambda item: (not item["is_dir"], item["name"].lower()))
    return {"prefix": prefix, "entries": entries[:1000], "truncated": len(entries) > 1000}


def sign_v4(method: str, path: str, query: str, headers: dict, payload: bytes, access_key: str,
            secret_key: str, region: str, service: str, amz_date: str) -> str:
    """AWS Signature Version 4 (dependency-free). Returns the Authorization header value."""
    names = sorted(name.lower() for name in headers)
    lowered = {name.lower(): " ".join(str(value).split()) for name, value in headers.items()}
    canonical_headers = "".join(f"{name}:{lowered[name]}\n" for name in names)
    signed_headers = ";".join(names)
    canonical = "\n".join([method, path or "/", query, canonical_headers, signed_headers,
                           hashlib.sha256(payload).hexdigest()])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret_key).encode()
    for part in (amz_date[:8], region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"


def read_billing_credentials() -> tuple[str, str]:
    path = Path(BILLING_CREDENTIALS)
    if not BILLING_CREDENTIALS or not path.is_file():
        raise ValueError(f"Billing credentials are not configured (expected {BILLING_CREDENTIALS or 'a credentials file'})")
    if path.stat().st_mode & 0o077:
        raise ValueError("Billing credentials file must not be readable by group or others; run chmod 600 on it")
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
        access_key, secret_key = str(values["access_key_id"]).strip(), str(values["secret_access_key"]).strip()
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("Billing credentials file must be JSON with access_key_id and secret_access_key")
    if not re.fullmatch(r"[A-Za-z0-9]{16,128}", access_key) or not 20 <= len(secret_key) <= 256:
        raise ValueError("Billing credentials look invalid")
    return access_key, secret_key


def post_cost_explorer(body: bytes, headers: dict) -> dict:
    request = urllib.request.Request("https://ce.us-east-1.amazonaws.com/", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read(1_000_000).decode("utf-8"))


def refresh_billing(data_dir: Path, now: datetime | None = None) -> dict:
    """Fetch this month's and last month's S3 spend from Cost Explorer (about $0.01 per call) and cache it."""
    access_key, secret_key = read_billing_credentials()
    now = now or datetime.now(timezone.utc)
    first_this = now.date().replace(day=1)
    first_last = (first_this - timedelta(days=1)).replace(day=1)
    body = json.dumps({"TimePeriod": {"Start": first_last.isoformat(), "End": (now.date() + timedelta(days=1)).isoformat()},
                       "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"],
                       "Filter": {"Dimensions": {"Key": "SERVICE", "Values": BILLING_SERVICES}}}).encode()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    headers = {"content-type": "application/x-amz-json-1.1", "host": "ce.us-east-1.amazonaws.com",
               "x-amz-date": amz_date, "x-amz-target": "AWSInsightsIndexService.GetCostAndUsage"}
    headers["Authorization"] = sign_v4("POST", "/", "", headers, body, access_key, secret_key, "us-east-1", "ce", amz_date)
    try:
        response = post_cost_explorer(body, headers)
    except Exception as exc:
        detail = getattr(exc, "read", lambda: b"")()[:300].decode("utf-8", "replace") if hasattr(exc, "read") else str(exc)
        raise ValueError("Cost Explorer request failed: " + redact(detail or str(exc))[:300])
    months = {}
    for period in response.get("ResultsByTime", []):
        start = period["TimePeriod"]["Start"][:7]
        total = period.get("Total", {}).get("UnblendedCost", {})
        months[start] = {"amount": round(float(total.get("Amount", 0) or 0), 2), "unit": total.get("Unit", "USD"),
                         "estimated": bool(period.get("Estimated", False))}
    result = {"this_month": months.get(first_this.strftime("%Y-%m")), "last_month": months.get(first_last.strftime("%Y-%m")),
              "month": first_this.strftime("%Y-%m"), "updated_at": iso()}
    target = data_dir / "billing.json"
    fd, temp = tempfile.mkstemp(prefix=target.name + ".", dir=data_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle); handle.flush(); os.fsync(handle.fileno())
    os.replace(temp, target)
    return result


def size_s3(data_dir: Path, rclone_bin: str) -> dict:
    """Measure the whole archive bucket once, on request, and cache the result.

    Read-only listing (rclone size); throttled with the same S3 request-rate and CPU limits as
    uploads. The cache lives in data/s3-size.json so the web app can show it without asking again.
    """
    global RUNNER_STATE
    limits = performance_settings(load_json(data_dir / "config.json"))
    command = [rclone_bin, "size", "--json", f"{REMOTE}:{BUCKET}", "--config", RCLONE_CONFIG, "--s3-no-check-bucket"]
    if limits["s3_requests_per_second"]:
        command.extend(["--tpslimit", str(limits["s3_requests_per_second"]),
                        "--tpslimit-burst", str(limits["s3_requests_per_second"])])
    RUNNER_STATE = "measuring"
    started = iso()
    try:
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600,
                              env={**os.environ, "GOMAXPROCS": str(limits["rclone_cpu_cores"])},
                              preexec_fn=lambda: constrain_rclone_process(limits["rclone_cpu_cores"]))
    finally:
        RUNNER_STATE = "idle"
    if proc.returncode:
        raise ValueError(f"S3 size check failed: {redact((proc.stderr or '').strip())[:300]}")
    parsed = json.loads(proc.stdout or "{}")
    result = {"bytes": max(0, int(parsed.get("bytes", 0) or 0)), "count": max(0, int(parsed.get("count", 0) or 0)),
              "started_at": started, "calculated_at": iso()}
    target = data_dir / "s3-size.json"
    fd, temp = tempfile.mkstemp(prefix=target.name + ".", dir=data_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle); handle.flush(); os.fsync(handle.fileno())
    os.replace(temp, target)
    return result


def process_control_requests(data_dir: Path, rclone_bin: str):
    global RESTART
    pending = data_dir / "control/pending"; results = data_dir / "control/results"
    pending.mkdir(parents=True, exist_ok=True); results.mkdir(parents=True, exist_ok=True)
    for path in sorted(pending.glob("*.json"), key=lambda item: item.stat().st_mtime):
        request = {}
        try:
            request = load_json(path); action = request.get("action")
            if float(request.get("expires_at", 0)) < time.time():
                raise ValueError("Control request expired before the runner could process it")
            if action == "inspect-rclone": result = inspect_rclone_remote(rclone_bin)
            elif action == "configure-rclone":
                configure_rclone_remote(request, rclone_bin); result = inspect_rclone_remote(rclone_bin)
            elif action == "browse-s3": result = browse_s3(request, rclone_bin)
            elif action == "size-s3": result = size_s3(data_dir, rclone_bin)
            elif action == "refresh-billing": result = refresh_billing(data_dir)
            elif action == "restart-runner":
                result = {"message": "Runner restart accepted"}; RESTART = True
            else: raise ValueError("Invalid control action")
            result.update({"request_id": request.get("id", path.stem), "status": "success", "updated_at": iso()})
        except Exception as exc:
            result = {"request_id": request.get("id", path.stem), "status": "failed",
                      "error": redact(str(exc)), "updated_at": iso()}
        finally:
            path.unlink(missing_ok=True)
        write_result_path = results / f"{result['request_id']}.json"
        fd, temp = tempfile.mkstemp(prefix=write_result_path.name + ".", dir=results)
        with os.fdopen(fd, "w", encoding="utf-8") as handle: json.dump(result, handle); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, write_result_path)
        if request.get("action") in {"inspect-rclone", "configure-rclone"}:
            status_path = data_dir / "rclone-status.json"
            fd, temp = tempfile.mkstemp(prefix=status_path.name + ".", dir=data_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(result, handle); handle.flush(); os.fsync(handle.fileno())
            os.replace(temp, status_path)


def main():
    global CHANGE_INDEX, BUCKET, REMOTE, RCLONE_CONFIG, BILLING_CREDENTIALS
    parser=argparse.ArgumentParser();parser.add_argument("--data-dir",default="/volume1/docker/synology-glacier-backup-manager/data");parser.add_argument("--log-dir",default="/volume1/docker/synology-glacier-backup-manager/logs");parser.add_argument("--rclone",default="rclone");parser.add_argument("--once",action="store_true")
    parser.add_argument("--billing-credentials",default=os.environ.get("GBM_BILLING_CREDENTIALS"),help="JSON file with a read-only Cost Explorer key (default: next to the rclone config).")
    parser.add_argument("--remote",default=os.environ.get("GBM_REMOTE"),help="Pinned rclone remote name (or GBM_REMOTE). Recommended.")
    parser.add_argument("--bucket",default=os.environ.get("GBM_BUCKET"),help="Pinned S3 bucket (or GBM_BUCKET). Recommended.")
    parser.add_argument("--rclone-config",default=os.environ.get("GBM_RCLONE_CONFIG"),help="Pinned rclone config path (or GBM_RCLONE_CONFIG). Recommended.")
    args=parser.parse_args()
    try: os.nice(10)
    except OSError: pass
    data=Path(args.data_dir);data.mkdir(parents=True,exist_ok=True)
    installation = load_json(data / "config.json")
    remote = str(installation.get("remote", "")); bucket = str(installation.get("bucket", "")); config_path = str(installation.get("rclone_config", ""))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", remote): raise ValueError("Unsafe rclone remote name")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{1,61}[A-Za-z0-9]", bucket): raise ValueError("Unsafe S3 bucket name")
    if not config_path.startswith("/") or "\x00" in config_path: raise ValueError("Unsafe rclone configuration path")
    # config.json is writable by the web container, so the destination must be pinned
    # outside it. When pins are supplied, a mismatching config.json is refused.
    pins = {"remote": (args.remote, remote), "bucket": (args.bucket, bucket), "rclone config path": (args.rclone_config, config_path)}
    unpinned = [name for name, (pinned, _) in pins.items() if not pinned]
    for name, (pinned, current) in pins.items():
        if pinned and pinned != current:
            raise ValueError(f"config.json {name} does not match the pinned value; refusing to start")
    REMOTE, BUCKET, RCLONE_CONFIG = remote, bucket, config_path
    BILLING_CREDENTIALS = args.billing_credentials or os.path.join(os.path.dirname(config_path), "aws-billing.json")
    PROTECTED_PATHS.extend([str(Path(args.data_dir).resolve()), str(Path(args.log_dir).resolve())])
    CHANGE_INDEX = ChangeIndex(data)
    log_dir=Path(args.log_dir);log_dir.mkdir(parents=True,exist_ok=True)
    handler=RotatingFileHandler(log_dir/"runner.log",maxBytes=10*1024*1024,backupCount=5)
    logging.basicConfig(level=logging.INFO,handlers=[handler],format="%(asctime)s %(levelname)s %(message)s")
    if unpinned:
        logging.warning("Destination not pinned for: %s. Pass --remote/--bucket/--rclone-config so a modified config.json cannot redirect uploads.", ", ".join(unpinned))
    rclone=shutil.which(args.rclone) or args.rclone
    lock=(data/"runner.lock").open("w");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    recover_interrupted_jobs(data)
    signal.signal(signal.SIGTERM,lambda *_:globals().__setitem__('STOP',True));signal.signal(signal.SIGINT,lambda *_:globals().__setitem__('STOP',True))
    threading.Thread(target=heartbeat,args=(data,rclone),daemon=True).start()
    threading.Thread(target=CHANGE_INDEX.watch,daemon=True).start()
    while not STOP:
        try:
            process_control_requests(data, rclone)
            if RESTART:
                os.execv(sys.executable, [sys.executable, *sys.argv])
            worked=run_once(data,rclone)
        except Exception: logging.exception("Runner loop failed");worked=False
        if args.once:return
        if not worked:time.sleep(2)


if __name__=="__main__":main()
