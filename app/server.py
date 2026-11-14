from __future__ import annotations

import json
import mimetypes
import os
import secrets
import threading
import time
import traceback
import uuid
import re
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from .auth import create_admin, new_session, verify_password
from .core import BUILTIN_EXCLUSIONS, init_db, load_config, queue_archive_job, queue_job, queue_upload_now, require_within_roots, save_config, upsert_result
from .version import VERSION

BASE = Path(__file__).parent
DATA = Path(os.environ.get("GBM_DATA_DIR", "/data"))
PORT = int(os.environ.get("GBM_PORT", "8787"))
DATA.mkdir(parents=True, exist_ok=True)
for sub in ("jobs/pending", "jobs/running", "jobs/results", "jobs/cancel", "control/pending", "control/results"):
    (DATA / sub).mkdir(parents=True, exist_ok=True)

UPDATE_STATUS = {"current": VERSION, "latest": None, "available": False, "checked_at": None, "error": None}
UPDATE_LOCK = threading.Lock()


def version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def check_for_updates_once() -> dict:
    """Read the public release marker without granting access to Docker or the host."""
    url = os.environ.get(
        "GBM_UPDATE_CHECK_URL",
        "https://raw.githubusercontent.com/impala84/synology-glacier-backup-manager/main/app/version.py",
    )
    try:
        request = Request(url, headers={"User-Agent": f"GlacierBackupManager/{VERSION}"})
        with urlopen(request, timeout=5) as response:
            payload = response.read(4096).decode("utf-8", errors="replace")
        match = re.search(r'^VERSION\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', payload, re.MULTILINE)
        if not match:
            raise ValueError("Release marker is invalid")
        latest = match.group(1)
        result = {"current": VERSION, "latest": latest,
                  "available": version_key(latest) > version_key(VERSION),
                  "checked_at": datetime.now().astimezone().isoformat(), "error": None}
    except Exception as exc:
        result = {"current": VERSION, "latest": None, "available": False,
                  "checked_at": datetime.now().astimezone().isoformat(),
                  "error": str(exc)[:160]}
    with UPDATE_LOCK:
        UPDATE_STATUS.update(result)
        return dict(UPDATE_STATUS)


def update_checker():
    if os.environ.get("GBM_UPDATE_CHECK", "true").lower() not in {"1", "true", "yes"}:
        return
    while True:
        check_for_updates_once()
        time.sleep(21600)


def queue_control(action: str, payload: dict | None = None) -> dict:
    request = {"id": str(uuid.uuid4()), "action": action,
               "created_at": datetime.now().astimezone().isoformat(),
               "expires_at": time.time() + 120, **(payload or {})}
    target = DATA / "control/pending" / f"{request['id']}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(request, handle); handle.flush(); os.fsync(handle.fileno())
    return {"id": request["id"], "status": "queued"}


def runner_connected() -> bool:
    try:
        status = json.loads((DATA / "runner-status.json").read_text())
        last_seen = datetime.fromisoformat(status["last_seen"])
        return (datetime.now(last_seen.tzinfo) - last_seen).total_seconds() < 30
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return False


def runner_supports_rclone_config() -> bool:
    try:
        status = json.loads((DATA / "runner-status.json").read_text())
        return "rclone-config-v1" in status.get("capabilities", [])
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def runner_supports(capability: str) -> bool:
    try:
        status = json.loads((DATA / "runner-status.json").read_text())
        return capability in status.get("capabilities", [])
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def runner_busy() -> bool:
    return any((DATA / "jobs/running").glob("*.json"))


def export_runner() -> bool:
    """Export the bundled runner and report whether its contents changed."""
    try:
        source = Path("/app/runner/glacier-runner.py")
        target = DATA / "runner" / "glacier-runner.py"
        if not source.exists():
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = source.read_bytes()
        if target.exists() and target.read_bytes() == payload:
            return False
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(payload)
        os.chmod(temporary, 0o755)
        os.replace(temporary, target)
        return True
    except Exception as exc:
        print(f"Runner export failed: {exc}", flush=True)
        return False


def export_and_restart_runner():
    """Load a changed runner automatically without interrupting active work."""
    if not export_runner():
        return
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if runner_connected():
            if not runner_supports_rclone_config():
                print("Runner updated, but this older runner requires one final manual restart", flush=True)
                return
            if not runner_busy():
                request = queue_control("restart-runner")
                print(f"Runner updated; automatic restart requested ({request['id']})", flush=True)
                return
        time.sleep(2)
    print("Runner updated, but automatic restart could not be requested within 10 minutes", flush=True)


def quarantine_pending_jobs():
    """Prevent pre-upgrade queued work from starting after a safety pause."""
    config = load_config(DATA)
    if not config.get("safety", {}).get("paused", True):
        return
    pending = DATA / "jobs" / "pending"
    cancelled = DATA / "jobs" / "cancelled"
    cancelled.mkdir(parents=True, exist_ok=True)
    for job in pending.glob("*.json"):
        try:
            os.replace(job, cancelled / job.name)
        except OSError as exc:
            print(f"Could not quarantine queued job {job.name}: {exc}", flush=True)


DB = init_db(DATA)
DB_LOCK = threading.Lock()
AUTH_PATH = DATA / "auth.json"
AUTH_LOCK = threading.Lock()
SESSIONS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
TRUST_PROXY = os.environ.get("GBM_TRUST_PROXY", "false").lower() == "true"
SCHEDULER_STATE = DATA / "scheduler-state.json"
SCHEDULE_GRACE = timedelta(hours=6)
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def browse_roots() -> list[str]:
    return [os.path.normpath(x) for x in os.environ.get("GBM_BROWSE_ROOTS", "").split(":") if x]


def schedule_due(now: datetime, time_text: str, last_run_date: str | None) -> bool:
    """True once per day, from the scheduled minute until a grace period passes (catch-up after downtime)."""
    hour, minute = (int(part) for part in time_text.split(":"))
    scheduled = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return scheduled <= now < scheduled + SCHEDULE_GRACE and last_run_date != now.date().isoformat()


def read_scheduler_state() -> dict:
    try:
        return json.loads(SCHEDULER_STATE.read_text())
    except (OSError, ValueError):
        return {}


def mark_schedule_handled(now: datetime | None = None) -> None:
    """Record today's slot as done so enabling or editing the schedule never triggers an immediate surprise run."""
    now = now or datetime.now()
    state = read_scheduler_state()
    state["last_run_date"] = now.date().isoformat()
    tmp = SCHEDULER_STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state)); os.replace(tmp, SCHEDULER_STATE)


def read_scheduler_last() -> str | None:
    return read_scheduler_state().get("last_run_date")


AUTO_MEASURE_INTERVAL = 7 * 86400
LAST_MEASURE_ATTEMPT = 0.0


def read_storage_size() -> dict | None:
    try:
        value = json.loads((DATA / "s3-size.json").read_text())
        return value if isinstance(value, dict) and "bytes" in value else None
    except (OSError, ValueError):
        return None


AUTO_BILLING_INTERVAL = 86400  # Cost Explorer bills about $0.01 per request, so refresh at most daily
LAST_BILLING_ATTEMPT = 0.0


def read_billing() -> dict | None:
    try:
        value = json.loads((DATA / "billing.json").read_text())
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def runner_billing_configured() -> bool:
    try:
        return bool(json.loads((DATA / "runner-status.json").read_text()).get("billing_configured"))
    except (OSError, ValueError):
        return False


def maybe_auto_billing() -> None:
    """Refresh the cached AWS bill once a day, only after the administrator has installed billing credentials."""
    global LAST_BILLING_ATTEMPT
    if time.time() - LAST_BILLING_ATTEMPT < 3600 or not runner_billing_configured():
        return
    cached = read_billing()
    try:
        age = time.time() - datetime.fromisoformat(cached["updated_at"]).timestamp() if cached else float("inf")
    except (KeyError, ValueError):
        age = float("inf")
    if age < AUTO_BILLING_INTERVAL:
        return
    if not (runner_connected() and runner_supports("billing-v1")) or any((DATA / "control/pending").glob("*.json")):
        return
    LAST_BILLING_ATTEMPT = time.time()
    queue_control("refresh-billing")


def maybe_auto_measure(cfg: dict) -> None:
    """Re-measure the bucket about weekly, only when the runner is idle and the engine is not paused."""
    global LAST_MEASURE_ATTEMPT
    if not cfg.get("cost", {}).get("auto_measure") or cfg.get("safety", {}).get("paused", True):
        return
    if time.time() - LAST_MEASURE_ATTEMPT < 3600:
        return
    size = read_storage_size()
    try:
        age = time.time() - datetime.fromisoformat(size["calculated_at"]).timestamp() if size else float("inf")
    except (KeyError, ValueError):
        age = float("inf")
    if age < AUTO_MEASURE_INTERVAL:
        return
    if not (runner_connected() and runner_supports("s3-size-v1")) or jobs_in_flight() \
            or any((DATA / "control/pending").glob("*.json")):
        return
    LAST_MEASURE_ATTEMPT = time.time()
    queue_control("size-s3")


def jobs_in_flight() -> bool:
    return any((DATA / "jobs/pending").glob("*.json")) or runner_busy()


def client_ip(handler) -> str:
    if TRUST_PROXY:
        forwarded = handler.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[-1].strip() or handler.client_address[0]
    return handler.client_address[0]


def purge_expired():
    now = time.time()
    for token in [t for t, s in list(SESSIONS.items()) if s["expires"] <= now]:
        SESSIONS.pop(token, None)
    for ip in list(LOGIN_ATTEMPTS):
        recent = [stamp for stamp in LOGIN_ATTEMPTS.get(ip, []) if now - stamp < 300]
        if recent: LOGIN_ATTEMPTS[ip] = recent
        else: LOGIN_ATTEMPTS.pop(ip, None)


def mount_pairs() -> list[tuple[str, str]]:
    pairs = []
    for item in os.environ.get("GBM_SOURCE_MOUNTS", "").split(","):
        if "=" in item:
            host, container = item.split("=", 1)
            pairs.append((os.path.normpath(host), os.path.normpath(container)))
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def host_to_container(host_path: str) -> str:
    host_path = os.path.normpath(host_path)
    for host, container in mount_pairs():
        if host_path == host or host_path.startswith(host + os.sep):
            return container + host_path[len(host):]
    raise ValueError("Path is outside configured read-only source mounts")


class Handler(BaseHTTPRequestHandler):
    server_version = "GlacierBackupManager/0.1"

    def log_message(self, fmt, *args):
        return

    def end_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()

    def fail(self, exc: Exception):
        """Expose validation messages, but never internal exception text."""
        if isinstance(exc, KeyError):
            return self.send_json({"error": f"Missing field: {exc.args[0]}"}, 400)
        if isinstance(exc, (ValueError, TypeError)):
            return self.send_json({"error": str(exc)}, 400)
        traceback.print_exc()
        return self.send_json({"error": "Internal error; see the container log"}, 500)

    def send_json(self, value, status=200):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        cookie = self.headers.get("Cookie", "")
        token = next((part.split("=", 1)[1] for part in cookie.split("; ") if part.startswith("gbm_session=")), "")
        session = SESSIONS.get(token)
        if session and session["expires"] > time.time():
            return token, session
        if token:
            SESSIONS.pop(token, None)
        return None, None

    def require_auth(self, csrf=False):
        token, session = self.session()
        if not session:
            self.send_json({"error": "Authentication required"}, 401); return None
        if csrf and not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            self.send_json({"error": "Invalid security token; refresh and try again"}, 403); return None
        return token, session

    def set_session(self, token: str):
        secure = os.environ.get("GBM_SECURE_COOKIES", "false").lower() == "true" or (
            TRUST_PROXY and self.headers.get("X-Forwarded-Proto", "").lower() == "https")
        cookie = f"gbm_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"
        if secure: cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)

    def body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length < 0 or length > 1_000_000:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                return self.send_json({"status": "ok"})
            if parsed.path == "/api/auth/status":
                _, session = self.session()
                return self.send_json({"configured": AUTH_PATH.exists(), "authenticated": bool(session), "username": session["username"] if session else None, "csrf": session["csrf"] if session else None})
            if parsed.path.startswith("/api/") and not self.require_auth(): return
            if parsed.path == "/api/state":
                return self.send_json(state())
            if parsed.path == "/api/rclone/status":
                status_path = DATA / "rclone-status.json"
                return self.send_json(json.loads(status_path.read_text()) if status_path.exists() else {"status": "unknown", "configured": None})
            if parsed.path.startswith("/api/control/results/"):
                request_id = parsed.path.rsplit("/", 1)[1]
                try: uuid.UUID(request_id)
                except ValueError: return self.send_json({"error": "Invalid request ID"}, 400)
                result_path = DATA / "control/results" / f"{request_id}.json"
                return self.send_json(json.loads(result_path.read_text()) if result_path.exists() else {"status": "pending"})
            if parsed.path == "/api/browse":
                path = parse_qs(parsed.query).get("path", [""])[0]
                include_files = parse_qs(parsed.query).get("files", ["0"])[0] == "1"
                return self.send_json(browse(path, include_files))
            if parsed.path.startswith("/api/runs/"):
                run_id = parsed.path.rsplit("/", 1)[1]
                with DB_LOCK:
                    row = DB.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
                return self.send_json(dict(row) if row else {"error": "Not found"}, 200 if row else 404)
            static_root = (BASE / "static").resolve()
            # Resolve before comparing: Path does not collapse '..', so an unresolved
            # parents check can be bypassed with /../ sequences.
            file_path = (static_root / ("index.html" if parsed.path == "/" else parsed.path.lstrip("/"))).resolve()
            if file_path.is_file() and static_root in file_path.parents:
                body = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mimetypes.guess_type(file_path)[0] or "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers(); self.wfile.write(body); return
            self.send_error(404)
        except Exception as exc:
            self.fail(exc)

    def do_POST(self):
        try:
            if self.path == "/api/auth/setup":
                data = self.body()
                with AUTH_LOCK:
                    record = create_admin(AUTH_PATH, data.get("username", ""), data.get("password", ""))
                token, session = new_session(record["username"]); SESSIONS[token] = session
                body = json.dumps({"ok": True, "username": session["username"], "csrf": session["csrf"]}, separators=(",", ":")).encode()
                self.send_response(201); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.set_session(token); self.end_headers(); self.wfile.write(body); return
            if self.path == "/api/auth/login":
                data = self.body(); ip = client_ip(self); now = time.time()
                attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(ip, []) if now - stamp < 300]
                if len(attempts) >= 8: return self.send_json({"error": "Too many attempts; try again in a few minutes"}, 429)
                record = json.loads(AUTH_PATH.read_text()) if AUTH_PATH.exists() else None
                valid = bool(record and secrets.compare_digest(str(data.get("username", "")), record["username"]) and verify_password(str(data.get("password", "")), record))
                if not valid:
                    attempts.append(now); LOGIN_ATTEMPTS[ip] = attempts
                    time.sleep(min(0.2 * len(attempts), 1.5)); return self.send_json({"error": "Invalid username or password"}, 401)
                LOGIN_ATTEMPTS.pop(ip, None); token, session = new_session(record["username"]); SESSIONS[token] = session
                body = json.dumps({"ok": True, "username": session["username"], "csrf": session["csrf"]}, separators=(",", ":")).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.set_session(token); self.end_headers(); self.wfile.write(body); return
            if self.path == "/api/auth/logout":
                auth = self.require_auth(csrf=True)
                if not auth: return
                SESSIONS.pop(auth[0], None); self.send_json({"ok": True}); return
            if not self.require_auth(csrf=True): return
            data = self.body(); config = load_config(DATA)
            if self.path == "/api/mappings":
                config["mappings"].append({
                    "id": str(uuid.uuid4()), "source": require_within_roots(data["source"], browse_roots()),
                    "destination": data["destination"], "enabled": bool(data.get("enabled", True)),
                })
                save_config(DATA, config); return self.send_json({"ok": True})
            if self.path == "/api/mappings/replace":
                existing = {m["source"]: m for m in config["mappings"]}
                replacements = []
                for item in data.get("mappings", []):
                    source = require_within_roots(item["source"], browse_roots())
                    previous = existing.get(source, {})
                    replacements.append({
                        "id": previous.get("id", str(uuid.uuid4())),
                        "source": source,
                        "destination": item["destination"],
                        "enabled": bool(item.get("enabled", previous.get("enabled", True))),
                        "exclusions": item.get("exclusions", previous.get("exclusions", [])),
                    })
                config["mappings"] = replacements
                save_config(DATA, config); return self.send_json({"ok": True})
            if self.path.startswith("/api/mappings/"):
                mapping_id = self.path.rsplit("/", 1)[1]
                found = next((m for m in config["mappings"] if m["id"] == mapping_id), None)
                if not found: return self.send_json({"error": "Mapping not found"}, 404)
                if "source" in data: data["source"] = require_within_roots(data["source"], browse_roots())
                for key in ("source", "destination", "enabled"):
                    if key in data: found[key] = data[key]
                save_config(DATA, config); return self.send_json({"ok": True})
            if self.path == "/api/settings":
                schedule = data.get("schedule", {})
                previous_schedule = dict(config["schedule"])
                config["schedule"].update({k: schedule[k] for k in ("enabled", "time", "max_age_hours") if k in schedule})
                if isinstance(data.get("safety", {}).get("paused"), bool):
                    config.setdefault("safety", {})["paused"] = data["safety"]["paused"]
                if "performance" in data:
                    config["performance"] = {key: int(value) for key, value in data["performance"].items()}
                if "cost" in data:
                    cost = data["cost"]
                    if "usd_per_gb_month" in cost: config["cost"]["usd_per_gb_month"] = float(cost["usd_per_gb_month"])
                    if "auto_measure" in cost: config["cost"]["auto_measure"] = bool(cost["auto_measure"])
                config["custom_exclusions"] = [str(x).strip() for x in data.get("custom_exclusions", []) if str(x).strip()]
                save_config(DATA, config)
                if config["safety"]["paused"]:
                    quarantine_pending_jobs()  # work queued before a pause must not run after a later resume
                if any(config["schedule"].get(k) != previous_schedule.get(k) for k in ("enabled", "time")):
                    mark_schedule_handled()
                return self.send_json({"ok": True})
            if self.path in {"/api/run/dry-run", "/api/run/backup"}:
                mode = "dry-run" if self.path.endswith("dry-run") else "backup"
                job = queue_job(DATA, mode, data.get("mapping_ids")); return self.send_json(job, 202)
            if self.path == "/api/upload-now":
                return self.send_json(queue_upload_now(DATA, str(data.get("path", ""))), 202)
            if self.path == "/api/archive":
                roots = browse_roots()
                sources = data.get("sources", [])
                source_paths = [os.path.normpath(str(value.get("source", ""))) for value in sources if isinstance(value, dict)]
                if len(source_paths) != len(sources) or any(not any(source == root or source.startswith(root + os.sep) for root in roots) for source in source_paths):
                    return self.send_json({"error": "Archive source is outside configured browse roots"}, 400)
                job = queue_archive_job(DATA, sources, data.get("destination", "Folder Archives"),
                                        data.get("format", "tar"), data.get("destination_mode", "source"))
                return self.send_json(job, 202)
            if self.path == "/api/rclone/refresh":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected"}, 409)
                if not runner_supports_rclone_config():
                    return self.send_json({"error": "The runner is connected but needs to be restarted to load the installation controls"}, 409)
                if runner_busy():
                    return self.send_json({"error": "Wait for the current backup job to finish"}, 409)
                return self.send_json(queue_control("inspect-rclone"), 202)
            if self.path == "/api/s3/browse":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected"}, 409)
                if not runner_supports("s3-browser-v1"):
                    return self.send_json({"error": "Restart the runner to load the S3 browser"}, 409)
                if runner_busy():
                    return self.send_json({"error": "Wait for the current backup job to finish"}, 409)
                prefix = str(data.get("prefix", "")).strip().strip("/")
                if "\x00" in prefix or any(part in {"", ".", ".."} for part in prefix.split("/") if prefix):
                    return self.send_json({"error": "Invalid S3 location"}, 400)
                return self.send_json(queue_control("browse-s3", {"prefix": prefix}), 202)
            if self.path == "/api/s3/size":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected"}, 409)
                if not runner_supports("s3-size-v1"):
                    return self.send_json({"error": "Restart the runner to enable storage measurement"}, 409)
                if runner_busy():
                    return self.send_json({"error": "Wait for the current backup job to finish"}, 409)
                return self.send_json(queue_control("size-s3"), 202)
            if self.path == "/api/billing/refresh":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected"}, 409)
                if not runner_supports("billing-v1"):
                    return self.send_json({"error": "Restart the runner to enable billing"}, 409)
                if not runner_billing_configured():
                    return self.send_json({"error": "Billing credentials are not installed on the NAS yet"}, 409)
                return self.send_json(queue_control("refresh-billing"), 202)
            if self.path == "/api/runner/restart":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected; use DSM Task Scheduler → Run"}, 409)
                if not runner_supports_rclone_config():
                    return self.send_json({"error": "This older runner must be restarted once from DSM or the command line"}, 409)
                if runner_busy():
                    return self.send_json({"error": "Wait for the current backup job to finish"}, 409)
                return self.send_json(queue_control("restart-runner"), 202)
            if self.path == "/api/rclone/configure":
                if not runner_connected():
                    return self.send_json({"error": "The bare-metal runner is disconnected"}, 409)
                if not runner_supports_rclone_config():
                    return self.send_json({"error": "The runner is connected but needs to be restarted to load the installation controls"}, 409)
                if runner_busy():
                    return self.send_json({"error": "Wait for the current backup job to finish"}, 409)
                if data.get("confirmation") != "REPLACE aws-archive":
                    return self.send_json({"error": "Type REPLACE aws-archive to confirm"}, 400)
                auth_mode = data.get("auth_mode", "keys")
                payload = {"auth_mode": auth_mode}
                if auth_mode == "keys":
                    payload.update({"access_key_id": str(data.get("access_key_id", "")),
                                    "secret_access_key": str(data.get("secret_access_key", ""))})
                return self.send_json(queue_control("configure-rclone", payload), 202)
            if self.path.startswith("/api/runs/") and self.path.endswith("/cancel"):
                run_id = self.path.split("/")[3]
                try: uuid.UUID(run_id)
                except ValueError: return self.send_json({"error": "Invalid job ID"}, 400)
                if not (DATA / "jobs/running" / f"{run_id}.json").exists():
                    return self.send_json({"error": "Job is no longer running"}, 409)
                marker = DATA / "jobs/cancel" / run_id
                marker.write_text("cancel", encoding="utf-8")
                return self.send_json({"ok": True}, 202)
            self.send_error(404)
        except Exception as exc:
            self.fail(exc)

    def do_DELETE(self):
        try:
            if not self.require_auth(csrf=True): return
            if not self.path.startswith("/api/mappings/"): return self.send_error(404)
            mapping_id = self.path.rsplit("/", 1)[1]
            config = load_config(DATA)
            config["mappings"] = [m for m in config["mappings"] if m["id"] != mapping_id]
            save_config(DATA, config); self.send_json({"ok": True})
        except Exception as exc:
            self.fail(exc)


def browse(path: str, include_files: bool = False) -> dict:
    roots = [x for x in os.environ.get("GBM_BROWSE_ROOTS", "").split(":") if x]
    if not roots: return {"path": "", "entries": [], "roots": [], "warning": "No browse roots configured"}
    if not path:
        return {
            "path": "Storage volumes", "parent": None, "roots": roots,
            "entries": [{"name": Path(root).name, "path": root, "selectable": False} for root in roots],
        }
    host_path = os.path.normpath(path)
    if not any(host_path == r or host_path.startswith(os.path.normpath(r) + os.sep) for r in roots):
        raise ValueError("Path is outside configured browse roots")
    container = Path(host_to_container(host_path)).resolve()
    allowed_container = [Path(host_to_container(r)).resolve() for r in roots]
    if not any(container == r or r in container.parents for r in allowed_container):
        raise ValueError("Resolved path escapes configured roots")
    hidden = {"@eaDir", "#recycle", "@Recycle", ".snapshot", "#snapshot"}
    entries = []
    for child in sorted(container.iterdir(), key=lambda p: p.name.casefold()):
        if child.name in hidden or child.name.startswith("@") or child.name.startswith("#") or child.is_symlink(): continue
        if not child.is_dir() and not (include_files and child.is_file()): continue
        entries.append({"name": child.name, "path": host_path.rstrip("/") + "/" + child.name,
                        "selectable": True, "is_dir": child.is_dir(),
                        "size": child.stat().st_size if child.is_file() else 0})
    parent = os.path.dirname(host_path)
    if host_path in roots:
        parent = ""
    elif not any(parent == r or parent.startswith(os.path.normpath(r) + os.sep) for r in roots):
        parent = None
    return {"path": host_path, "parent": parent, "entries": entries, "roots": roots}


def ingest_results():
    while True:
        try:
            for path in (DATA / "jobs/results").glob("*.json"):
                result = json.loads(path.read_text())
                with DB_LOCK: upsert_result(DB, result)
                path.rename(path.with_suffix(".ingested"))
        except Exception:
            traceback.print_exc()
        time.sleep(2)


def scheduler():
    if not SCHEDULER_STATE.exists():
        mark_schedule_handled()  # first start: do not fire a catch-up run for a slot that has already passed
    while True:
        try:
            for request in (DATA / "control/pending").glob("*.json"):
                try:
                    body = json.loads(request.read_text())
                    if float(body.get("expires_at", 0)) < time.time(): request.unlink(missing_ok=True)
                except (OSError, ValueError, json.JSONDecodeError):
                    request.unlink(missing_ok=True)
            purge_expired()
            cfg = load_config(DATA); now = datetime.now()
            maybe_auto_measure(cfg)
            maybe_auto_billing()
            if (cfg["schedule"]["enabled"] and not jobs_in_flight()
                    and schedule_due(now, cfg["schedule"]["time"], read_scheduler_last())):
                queue_job(DATA, "backup", trigger="schedule"); mark_schedule_handled(now)
        except ValueError:
            pass
        except Exception:
            traceback.print_exc()
        time.sleep(20)


def state():
    cfg = load_config(DATA)
    with DB_LOCK:
        rows = [dict(row) for row in DB.execute("SELECT * FROM runs ORDER BY COALESCE(started_at,'') DESC LIMIT 50")]
        archive_rows = [dict(row) for row in DB.execute(
            "SELECT finished_at,summary FROM runs WHERE mode='archive' AND status='success' "
            "ORDER BY COALESCE(finished_at,'') DESC"
        )]
    archive_history = {}
    for row in archive_rows:
        try:
            for item in json.loads(row.get("summary") or "[]"):
                source = item.get("source") if item.get("outcome") == "archive_uploaded" else None
                if source and source not in archive_history:
                    archive_history[source] = row.get("finished_at")
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    def queued_jobs(folder: str, status: str):
        jobs = []
        for path in (DATA / "jobs" / folder).glob("*.json"):
            try:
                job = json.loads(path.read_text())
                jobs.append({
                    "id": job.get("id", path.stem), "mode": job.get("mode", "backup"),
                    "trigger": job.get("trigger", "manual"), "created_at": job.get("created_at"),
                    "status": status, "mapping_count": len(job.get("mapping_ids", [])),
                    "source_count": len(job.get("sources", [])),
                })
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return sorted(jobs, key=lambda job: job.get("created_at") or "")
    active = queued_jobs("running", "running")
    for job in active:
        job["cancel_requested"] = (DATA / "jobs/cancel" / job["id"]).exists()
    pending = queued_jobs("pending", "queued")
    runner = {"connected": False, "last_seen": None}
    status_path = DATA / "runner-status.json"
    try:
        status = json.loads(status_path.read_text())
        last_seen = datetime.fromisoformat(status["last_seen"])
        runner = {**status, "connected": (datetime.now(last_seen.tzinfo) - last_seen).total_seconds() < 30}
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        pass
    safe_cfg = {**cfg, "builtin_exclusions": BUILTIN_EXCLUSIONS,
                "safety_flags": ["copy only", "no remote traversal", "persistent local change index",
                                 "bounded transfer and checker settings", "automatic thermal pause", "--s3-no-check-bucket"]}
    with UPDATE_LOCK:
        update = dict(UPDATE_STATUS)
    measured = read_storage_size()
    with DB_LOCK:
        added = DB.execute(
            "SELECT COALESCE(SUM(bytes),0) FROM runs WHERE status='success' AND mode IN ('backup','archive','upload-now') "
            "AND finished_at > ?", ((measured or {}).get("calculated_at", "9999"),)).fetchone()[0]
        lifetime = DB.execute("SELECT COALESCE(SUM(bytes),0) FROM runs WHERE status='success' "
                              "AND mode IN ('backup','archive','upload-now')").fetchone()[0]
    storage = {"measured": measured, "added_since_bytes": int(added or 0), "uploaded_total_bytes": int(lifetime or 0),
               "billing": read_billing(), "billing_configured": runner_billing_configured()}
    schedule_status = {"now": datetime.now().astimezone().isoformat(), "tz": os.environ.get("TZ", ""),
                       "last_run_date": read_scheduler_last()}
    return {"config": safe_cfg, "runs": rows, "active": active, "pending": pending,
            "runner": runner, "archive_history": archive_history, "update": update,
            "schedule_status": schedule_status, "storage": storage}


def main():
    print(f"Glacier Backup Manager starting on port {PORT}", flush=True)
    quarantine_pending_jobs()
    threading.Thread(target=export_and_restart_runner, daemon=True).start()
    threading.Thread(target=ingest_results, daemon=True).start()
    threading.Thread(target=scheduler, daemon=True).start()
    threading.Thread(target=update_checker, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("Glacier Backup Manager ready", flush=True)
    server.serve_forever()


if __name__ == "__main__": main()
