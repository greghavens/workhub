import fnmatch
import hashlib
import json
from datetime import datetime

import pathspec


class HubError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def timestamp(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def specification(issue):
    return {"title": issue["title"], "body": issue.get("body") or "", "url": issue["html_url"]}


def labels(issue):
    return {i["name"] if isinstance(i, dict) else i for i in issue.get("labels", [])}


def latest_approval_event(events):
    relevant = [
        e
        for e in events
        if e.get("event") in {"labeled", "unlabeled"}
        and e.get("label", {}).get("name") == "agent:approved"
    ]
    return max(relevant, key=lambda e: (e["created_at"], e["id"])) if relevant else None


def eligible_issue(issue):
    return (
        issue["state"] == "open"
        and "pull_request" not in issue
        and "agent:approved" in labels(issue)
        and "agent:blocked" not in labels(issue)
    )


def approval_matches(task, issue, policy_hash, event):
    return (
        eligible_issue(issue)
        and task.approval
        and task.approval["spec_hash"] == digest(specification(issue))
        and task.policy_hash == policy_hash
        and event is not None
        and event["event"] == "labeled"
        and task.approval["label_event_id"] == event["id"]
    )


DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "mix.exs",
    "mix.lock",
}


def validate_paths(files, policy):
    allow = pathspec.PathSpec.from_lines("gitwildmatch", policy["allowed_paths"])
    deny = pathspec.PathSpec.from_lines("gitwildmatch", policy["forbidden_paths"])
    for file in files:
        # Renames must comply at both ends; otherwise a rename evades the scope restriction.
        for path in {file["filename"], file.get("previous_filename", file["filename"])}:
            if (
                path.startswith("/")
                or ".." in path.split("/")
                or not allow.match_file(path)
                or deny.match_file(path)
            ):
                raise HubError(409, f"Changed path is outside the contract: {path}")
            filename = path.rsplit("/", 1)[-1]
            if not policy["dependency_changes"] and (
                filename in DEPENDENCY_FILES or fnmatch.fnmatch(filename, "requirements*.txt")
            ):
                raise HubError(409, f"Dependency changes are not approved: {path}")
