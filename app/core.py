from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

BUCKET = os.environ.get("GBM_BUCKET", "example-archive-bucket").strip()
REMOTE = os.environ.get("GBM_REMOTE", "aws-archive").strip()
CONFIG_PATH = os.environ.get("GBM_RCLONE_CONFIG", "/volume1/@rclone/rclone.conf").strip()
BUILTIN_EXCLUSIONS = [
    "**/@eaDir/**", "**/#recycle/**", "**/@Recycle/**",
    "**/.snapshot/**", "**/#snapshot/**", "**/.DS_Store", "**/Thumbs.db",
]
DEFAULT_CONFIG = {
    "version": 5,
    "remote": REMOTE,
    "bucket": BUCKET,
    "rclone_config": CONFIG_PATH,
    "schedule": {"enabled": False, "time": "02:00", "max_age_hours": 48},
    "safety": {"paused": True},
    "performance": {
        "scan_batch_entries": 100, "scan_pause_ms": 50,
        "transfers": 1, "checkers": 1, "bandwidth_mib": 0,
        "s3_requests_per_second": 8,
        "temperature_pause_c": 65, "temperature_resume_c": 60,
        "rclone_cpu_cores": 1,
    },
    "cost": {"usd_per_gb_month": 0.00099, "auto_measure": True},
    "custom_exclusions": [],
    "mappings": [],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_config(data_dir: Path) -> dict:
    path = data_dir / "config.json"
    if not path.exists():
        atomic_json(path, DEFAULT_CONFIG)
    with path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if int(config.get("version", 1)) < 2:
        config["version"] = 2
        config.setdefault("schedule", {})["enabled"] = False
        config["safety"] = {"paused": True}
        atomic_json(path, config)
    if int(config.get("version", 1)) < 3:
        config["version"] = 3
        config["performance"] = DEFAULT_CONFIG["performance"].copy()
        atomic_json(path, config)
    if int(config.get("version", 1)) < 4:
        config["version"] = 4
        config.setdefault("performance", DEFAULT_CONFIG["performance"].copy())["bandwidth_mib"] = 0
        atomic_json(path, config)
    if int(config.get("version", 1)) < 5:
        config["version"] = 5
        config.setdefault("performance", DEFAULT_CONFIG["performance"].copy())["rclone_cpu_cores"] = 1
        atomic_json(path, config)
    config.setdefault("safety", {"paused": True})
    config.setdefault("performance", DEFAULT_CONFIG["performance"].copy())
    config.setdefault("cost", DEFAULT_CONFIG["cost"].copy())
    validate_config(config)
    return config


def save_config(data_dir: Path, config: dict) -> None:
    validate_config(config)
    atomic_json(data_dir / "config.json", config)


DEFAULT_PROTECTED_PATHS = ("/volume1/docker/synology-glacier-backup-manager",)


def protected_paths() -> list[str]:
    """Folders that must never be backed up: this app's own data, logs and rclone credentials."""
    configured = [os.path.normpath(p) for p in os.environ.get("GBM_PROTECTED_PATHS", "").split(":") if p]
    config_dir = os.path.dirname(os.path.normpath(CONFIG_PATH))
    return [*DEFAULT_PROTECTED_PATHS, *configured, config_dir]


def validate_source(path: str) -> str:
    """Normalise first, then validate, so '/volume1/../etc' cannot slip through."""
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("Source must be an absolute Synology volume path")
    normalized = os.path.normpath(path)
    if not re.fullmatch(r"/volume[0-9]+(?:/.*)?", normalized):
        raise ValueError("Source must be an absolute Synology volume path")
    parts = normalized.split("/")[2:]
    if not parts:
        raise ValueError("Select a specific folder, not an entire volume")
    if parts[0].startswith(("@", "#")):
        raise ValueError("Synology system folders cannot be a backup source")
    for protected in protected_paths():
        if normalized == protected or normalized.startswith(protected.rstrip("/") + "/"):
            raise ValueError("This folder holds the manager's own data or credentials and cannot be a source")
    return normalized


def require_within_roots(path: str, roots: list[str]) -> str:
    """Validate a source and require it to sit inside one of the configured browse roots."""
    value = validate_source(path)
    normalized_roots = [os.path.normpath(root) for root in roots if root]
    if not any(value == root or value.startswith(root + os.sep) for root in normalized_roots):
        raise ValueError("Source is outside configured browse roots")
    return value


def validate_prefix(prefix: str) -> str:
    value = prefix.strip().strip("/")
    if not value or "\x00" in value or value.startswith("."):
        raise ValueError("S3 prefix is required")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Invalid S3 prefix")
    return value


def validate_config(config: dict) -> None:
    if config.get("remote") != REMOTE or config.get("bucket") != BUCKET:
        raise ValueError("Remote and bucket are fixed safety settings")
    if config.get("rclone_config") != CONFIG_PATH:
        raise ValueError("rclone config path is fixed")
    if not isinstance(config.get("safety", {}).get("paused"), bool):
        raise ValueError("Invalid runner safety state")
    performance = config.get("performance", {})
    limits = {
        "scan_batch_entries": (10, 1000), "scan_pause_ms": (10, 5000),
        "transfers": (1, 4), "checkers": (1, 8), "bandwidth_mib": (0, 10000),
        "s3_requests_per_second": (0, 20),
        "temperature_pause_c": (45, 90), "temperature_resume_c": (40, 85),
        "rclone_cpu_cores": (1, 4),
    }
    for key, (minimum, maximum) in limits.items():
        value = performance.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"Invalid performance setting: {key}")
    if performance["temperature_resume_c"] >= performance["temperature_pause_c"]:
        raise ValueError("Resume temperature must be below pause temperature")
    cost = config.get("cost", {})
    rate = cost.get("usd_per_gb_month")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 < rate <= 1:
        raise ValueError("Storage price must be greater than 0 and at most 1 USD per GB-month")
    if not isinstance(cost.get("auto_measure"), bool):
        raise ValueError("Invalid automatic storage measurement setting")
    hours = int(config.get("schedule", {}).get("max_age_hours", 0))
    if not 1 <= hours <= 720:
        raise ValueError("Modification window must be between 1 and 720 hours")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", config.get("schedule", {}).get("time", "")):
        raise ValueError("Schedule time must use HH:MM")
    seen = set()
    for mapping in config.get("mappings", []):
        mapping["source"] = validate_source(mapping["source"])
        mapping["destination"] = validate_prefix(mapping["destination"])
        clean_exclusions = []
        for exclusion in mapping.get("exclusions", []):
            value = str(exclusion).strip().strip("/")
            if not value or any(part in {"", ".", ".."} for part in value.split("/")):
                raise ValueError("Invalid folder exclusion")
            clean_exclusions.append(value)
        mapping["exclusions"] = sorted(set(clean_exclusions))
        if mapping["source"] in seen:
            raise ValueError("Each source folder may appear only once")
        seen.add(mapping["source"])


def queue_job(data_dir: Path, mode: str, mapping_ids: list[str] | None = None, trigger: str = "manual") -> dict:
    if mode not in {"dry-run", "backup"}:
        raise ValueError("Invalid run mode")
    config = load_config(data_dir)
    if config.get("safety", {}).get("paused", True):
        raise ValueError("Backup engine is paused for NAS safety")
    enabled = [m for m in config["mappings"] if m.get("enabled", True)]
    if mapping_ids:
        requested = set(mapping_ids)
        enabled = [m for m in enabled if m["id"] in requested]
    if not enabled:
        raise ValueError("No enabled mappings selected")
    job = {
        "id": str(uuid.uuid4()), "mode": mode, "trigger": trigger,
        "created_at": now_iso(), "mapping_ids": [m["id"] for m in enabled],
    }
    atomic_json(data_dir / "jobs" / "pending" / f"{job['id']}.json", job)
    return job


def queue_upload_now(data_dir: Path, selected_path: str) -> dict:
    config = load_config(data_dir)
    if config.get("safety", {}).get("paused", True):
        raise ValueError("Backup engine is paused for NAS safety")
    path = validate_source(selected_path)
    mappings = [m for m in config.get("mappings", []) if m.get("enabled", True)
                and (path == m["source"] or path.startswith(m["source"].rstrip("/") + "/"))]
    if not mappings:
        raise ValueError("Select a file or folder inside an enabled source mapping")
    mapping = max(mappings, key=lambda item: len(item["source"]))
    relative = os.path.relpath(path, mapping["source"])
    relative = "" if relative == "." else relative
    if any(part in {"", ".", "..", "@eaDir", "#recycle", "@Recycle", ".snapshot", "#snapshot"}
           for part in relative.split("/") if relative):
        raise ValueError("This path is excluded from backups")
    job = {"id": str(uuid.uuid4()), "mode": "upload-now", "trigger": "manual",
           "created_at": now_iso(), "mapping_ids": [mapping["id"]], "selected_path": relative}
    atomic_json(data_dir / "jobs" / "pending" / f"{job['id']}.json", job)
    return job


def queue_archive_job(data_dir: Path, sources: list[dict], destination: str,
                      archive_format: str = "tar", destination_mode: str = "source") -> dict:
    config = load_config(data_dir)
    if config.get("safety", {}).get("paused", True):
        raise ValueError("Backup engine is paused for NAS safety")
    if archive_format not in {"tar", "tar.gz"}:
        raise ValueError("Archive format must be tar or tar.gz")
    if destination_mode not in {"source", "parent", "custom"}:
        raise ValueError("Invalid archive destination mode")
    clean_sources = []
    seen = set()
    for item in sources:
        if not isinstance(item, dict): raise ValueError("Invalid archive folder selection")
        value = validate_source(str(item.get("source", "")))
        exclusions = []
        for exclusion in item.get("exclusions", []):
            relative = str(exclusion).strip().strip("/")
            if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
                raise ValueError("Invalid archive folder exclusion")
            exclusions.append(relative)
        if value not in seen:
            clean_sources.append({"source": value, "exclusions": sorted(set(exclusions))}); seen.add(value)
    if not clean_sources or len(clean_sources) > 20:
        raise ValueError("Select between 1 and 20 folders")
    job = {
        "id": str(uuid.uuid4()), "mode": "archive", "trigger": "manual",
        "created_at": now_iso(), "sources": clean_sources,
        "destination": "" if destination_mode in {"source", "parent"} else validate_prefix(destination),
        "destination_mode": destination_mode, "archive_format": archive_format,
    }
    atomic_json(data_dir / "jobs" / "pending" / f"{job['id']}.json", job)
    return job


def init_db(data_dir: Path) -> sqlite3.Connection:
    db = sqlite3.connect(data_dir / "history.sqlite3", check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS runs (
      id TEXT PRIMARY KEY, mode TEXT NOT NULL, trigger TEXT NOT NULL,
      started_at TEXT, finished_at TEXT, status TEXT NOT NULL,
      files INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, duration REAL DEFAULT 0,
      error TEXT DEFAULT '', log TEXT DEFAULT '')""")
    columns = {row[1] for row in db.execute("PRAGMA table_info(runs)")}
    if "candidates" not in columns:
        db.execute("ALTER TABLE runs ADD COLUMN candidates INTEGER")
    if "summary" not in columns:
        db.execute("ALTER TABLE runs ADD COLUMN summary TEXT DEFAULT ''")
    db.commit()
    return db


def upsert_result(db: sqlite3.Connection, result: dict) -> None:
    values = {**result, "candidates": result.get("candidates"), "summary": result.get("summary", "")}
    db.execute("""INSERT INTO runs(id,mode,trigger,started_at,finished_at,status,files,candidates,bytes,duration,error,log,summary)
      VALUES(:id,:mode,:trigger,:started_at,:finished_at,:status,:files,:candidates,:bytes,:duration,:error,:log,:summary)
      ON CONFLICT(id) DO UPDATE SET finished_at=excluded.finished_at,status=excluded.status,
      files=excluded.files,candidates=excluded.candidates,bytes=excluded.bytes,duration=excluded.duration,error=excluded.error,log=excluded.log,summary=excluded.summary""", values)
    db.commit()
