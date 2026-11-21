import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def config_path():
    return Path(os.getenv("WORKHUB_CLIENT_CONFIG", "~/.config/workhub/client.json")).expanduser()


def write_private(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW rejects a pre-existing symlink; create the file with owner-only permissions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(content)


class ClientError(Exception):
    def __init__(self, message, status=0):
        self.status = status
        super().__init__(message)


class Client:
    def __init__(self, url=None, token=None, admin=False, allow_anonymous=False):
        saved = json.loads(config_path().read_text()) if config_path().exists() else {}
        url = url or os.getenv("WORKHUB_URL") or saved.get("url", "http://127.0.0.1:8000")
        parsed = urlsplit(url)
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or (
                parsed.scheme != "https"
                and not (
                    parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                )
            )
        ):
            raise ClientError("Use HTTPS for remote hubs")
        token = (
            token
            or os.getenv("WORKHUB_ADMIN_TOKEN" if admin else "WORKHUB_TOKEN")
            or (saved.get("token") if not admin or saved.get("role") == "admin" else None)
        )
        if not token and not allow_anonymous:
            raise ClientError("Set WORKHUB_ADMIN_TOKEN" if admin else "Run workhub login first")
        self.url = url.rstrip("/")
        self.http = httpx.Client(
            base_url=self.url,
            headers={"Authorization": f"Bearer {token}"} if token else {},
            timeout=300,
        )

    def call(self, method, path, **kwargs):
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ClientError("Hub is unavailable; retry using the same idempotency key") from exc
        if response.is_error:
            try:
                message = str(response.json().get("detail", response.status_code))
            except ValueError:
                message = f"Hub returned HTTP {response.status_code}"
            raise ClientError(message, response.status_code)
        return response.json()


class Heartbeats:
    """Lease timers live in the local adapter, not in the model's context."""

    def __init__(self, client):
        self.client = client
        self.lock = threading.Lock()
        self.assignments = {}
        self.errors = {}
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def track(self, result):
        if "contract" not in result or result["assignment"]["state"] != "leased":
            return
        task_id = result["contract"]["contract_id"]
        with self.lock:
            self.assignments[task_id] = result["assignment"].copy()
            self.assignments[task_id]["renew_at"] = min(
                int(time.time()) + 60, result["assignment"]["expires_at"] - 15
            )
            self.errors.pop(task_id, None)

    def forget(self, task_id):
        with self.lock:
            self.assignments.pop(task_id, None)

    def run(self):
        while not self.stop_event.wait(5):
            with self.lock:
                assignments = list(self.assignments.items())
            for task_id, assignment in assignments:
                now = int(time.time())
                if now < assignment.get("renew_at", assignment["expires_at"] - 120):
                    continue
                if assignment["expires_at"] <= now:
                    with self.lock:
                        self.errors[task_id] = (
                            "Lease expired. Stop work and inspect the assignment."
                        )
                    self.forget(task_id)
                    continue
                try:
                    result = self.client.call(
                        "POST",
                        f"/v1/work/{task_id}/heartbeat",
                        json={
                            "attempt_id": assignment["attempt_id"],
                            "generation": assignment["generation"],
                        },
                    )
                    self.track(result)
                except ClientError as exc:
                    with self.lock:
                        self.errors[task_id] = str(exc)
                    if exc.status in {401, 403, 404, 409}:
                        self.forget(task_id)

    def close(self):
        self.stop_event.set()


FORK_COMMAND = ["gh", "repo", "fork"]


def ensure_push_target(provision, run, attempts=20, pause=3):
    """Wait until the assigned push repository exists.

    When the hub reports that a fork is needed, run its ``gh repo fork`` command once with the
    contributor's own GitHub CLI; the hub never creates forks. GitHub creates forks
    asynchronously, so the hub is re-checked a bounded number of times.
    """
    forked = False
    for attempt in range(attempts):
        if attempt:
            time.sleep(pause)
        result = provision()
        if result["status"] == "ready":
            return result
        if result["status"] != "fork_required":
            raise ClientError(f"Unexpected provisioning status: {result['status']}")
        command = result["command"]
        if command[:3] != FORK_COMMAND:
            raise ClientError("Hub returned an unexpected fork command")
        if not forked:
            run(command)
            forked = True
    raise ClientError(
        f"Fork {result['repository']} is still not visible to the hub; "
        "check it exists on GitHub, then retry"
    )
