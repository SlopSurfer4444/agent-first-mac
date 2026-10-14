#!/usr/bin/python3
"""Concise SessionStart guidance; legacy policing commands are inert.

Explicit provenance diagnostics retain their historical strict helpers. They
are not consulted at SessionStart, PreToolUse or Stop and grant no native trust.
"""

import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys


REGISTRY_LIMIT = 65536
EVENT_LIMIT = 65536
SAFE_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"
REGISTRY_ROOT = re.compile(
    r"^\$HOME/AIDev/(?:control|repos/"
    + SAFE_SEGMENT
    + r"(?:/"
    + SAFE_SEGMENT
    + r")*|worktrees/"
    + SAFE_SEGMENT
    + r"(?:/"
    + SAFE_SEGMENT
    + r")*)$"
)
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]*$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class RegistryError(Exception):
    pass


def canonical_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)


def payload(require_cwd=True):
    try:
        raw = sys.stdin.read(EVENT_LIMIT + 1)
        if len(raw) > EVENT_LIMIT:
            raise ValueError("event limit")
        value = json.loads(raw)
    except Exception:
        if require_cwd:
            raise SystemExit(2)
        return {"hook_event_name": "SessionStart"}
    if not isinstance(value, dict) or (require_cwd and not isinstance(value.get("cwd"), str)):
        if require_cwd:
            raise SystemExit(2)
        return {"hook_event_name": "SessionStart"}
    return value


def is_within(value, parent):
    return value == parent or parent in value.parents


def reject_symlink_components(home, path):
    try:
        relative = path.relative_to(home)
    except ValueError as error:
        raise RegistryError("outside canonical home") from error
    current = home
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RegistryError("symlink component")


def strict_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RegistryError("duplicate JSON key")
            value[key] = item
        return value

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > REGISTRY_LIMIT:
            raise RegistryError("registry file")
        return json.loads(path.read_text(errors="strict"), object_pairs_hook=unique)
    except RegistryError:
        raise
    except Exception as error:
        raise RegistryError("invalid registry JSON") from error


def trusted_roots(home, registry_path=None):
    home = Path(home).resolve(strict=True)
    registry = (
        Path(registry_path)
        if registry_path is not None
        else home / "AIDev/control/manifests/trusted-repos.json"
    )
    reject_symlink_components(home, registry)
    value = strict_json(registry)
    if set(value) != {"schema", "repositories"} or value["schema"] != 1:
        raise RegistryError("registry shape")
    if not isinstance(value["repositories"], list) or not value["repositories"]:
        raise RegistryError("registry items")
    roots = set()
    identifiers = set()
    expected_keys = {
        "adoptedCommit",
        "canonicalRoot",
        "id",
        "provenance",
        "route",
        "trust",
    }
    for item in value["repositories"]:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise RegistryError("registry item")
        if not isinstance(item["id"], str) or not IDENTIFIER.fullmatch(item["id"]):
            raise RegistryError("registry id")
        if item["id"] in identifiers:
            raise RegistryError("duplicate registry id")
        identifiers.add(item["id"])
        raw_root = item["canonicalRoot"]
        if not isinstance(raw_root, str) or not REGISTRY_ROOT.fullmatch(raw_root):
            raise RegistryError("registry root")
        if item["route"] != "trusted" or not COMMIT.fullmatch(item["adoptedCommit"]):
            raise RegistryError("registry policy")
        if raw_root == "$HOME/AIDev/control":
            if (
                item["trust"] != "trusted-control"
                or item["provenance"] != "reviewed-control"
            ):
                raise RegistryError("control registry policy")
        elif (
            item["trust"] != "trusted-repo"
            or item["provenance"] != "reviewed-clone"
        ):
            raise RegistryError("repository registry policy")
        candidate = home / raw_root[len("$HOME/") :]
        reject_symlink_components(home, candidate)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise RegistryError("missing registry root") from error
        if resolved != candidate or not resolved.is_dir() or resolved in roots:
            raise RegistryError("non-canonical registry root")
        roots.add(resolved)
    return roots


def git_root(cwd, home):
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "-C",
            str(cwd),
            "rev-parse",
            "--show-toplevel",
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    if len(lines) != 1 or not lines[0].startswith("/"):
        raise RegistryError("invalid Git root")
    try:
        root = Path(lines[0]).resolve(strict=True)
    except OSError as error:
        raise RegistryError("missing Git root") from error
    if not root.is_dir():
        raise RegistryError("invalid Git root")
    return root


def zone(cwd, home=None, registry_path=None):
    try:
        owner_home = (
            canonical_home() if home is None else Path(home).resolve(strict=True)
        )
        current = Path(cwd).resolve(strict=True)
        if not current.is_dir():
            return "invalid"
        control = owner_home / "AIDev/control"
        control_worktrees = owner_home / "AIDev/worktrees/control"
        quarantine = owner_home / "AIDev/quarantine"
        if is_within(current, control) or is_within(current, control_worktrees):
            return "control"
        if is_within(current, quarantine):
            return "quarantine"
        root = git_root(current, owner_home)
        if root is None:
            return "generic"
        roots = trusted_roots(owner_home, registry_path=registry_path)
        return "trusted_repo" if root in roots else "unknown_git"
    except (OSError, RegistryError, RuntimeError, ValueError):
        return "registry_invalid"


def project_context(cwd, home=None):
    """Bounded SessionStart guidance, never registry/native trust admission."""
    try:
        if not isinstance(cwd, (str, Path)):
            return "unavailable"
        text = str(cwd)
        if len(text) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in text):
            return "unavailable"
        if not Path(text).is_absolute():
            return "unavailable"
        owner_home = canonical_home() if home is None else Path(home).resolve(strict=True)
        current = Path(text).resolve(strict=True)
        if not current.is_dir() or not os.access(current, os.R_OK | os.X_OK):
            return "unavailable"
        if is_within(current, owner_home / "AIDev/control") or is_within(current, owner_home / "AIDev/worktrees/control"):
            return "control"
        if is_within(current, owner_home / "AIDev/quarantine"):
            return "quarantine"
        # A Git checkout, worktree and ordinary directory get identical neutral
        # guidance. Do not inspect Git metadata or consult the custom registry.
        return "project"
    except (OSError, RuntimeError, ValueError):
        return "unavailable"


def context(value, home=None, registry_path=None):
    route = project_context(value.get("cwd"), home=home)
    project_boundary = (
        "Follow the closest repository/AGENTS.md and lockfile for authorized read/edit "
        "and repo-local development; no control registration or workstation doctor. "
        "This grants no repository trust or permissions: native permission policy "
        "still applies. Execute unknown external code only in quarantine/sandbox. "
        "For workstation changes use $manage-workstation and docs/harness-operations.md."
    )
    messages = {
        "control": (
            "Control source can affect live hooks: isolate source changes. Read the "
            "current decision in ARCHITECTURE.md and docs/harness-operations.md, then "
            "the affected contract. Source-only work needs no live doctor. Protected "
            "apply retains actual source, target, recovery and native authority checks."
        ),
        "quarantine": (
            "This input is quarantined: keep reads inside the exact workspace; "
            "do not use secrets, user MCP/apps, plugins, network, control, or aid-admin."
        ),
        "project": "Bounded project-directory context. " + project_boundary,
        "unavailable": (
            "Working-directory context is unavailable; do not infer repository "
            "identity or trust. " + project_boundary
        ),
    }
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "additionalContext": messages[route],
                    "hookEventName": "SessionStart",
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def workstation_bypass(command):
    """Legacy API kept benign while exact owned definitions are retired."""
    return False


def warn(value):
    """No regex policing; actual execution adapters own affected checks."""
    return None


def verify(value, home=None, registry_path=None):
    """Ending source-only analysis is not an apply or acceptance boundary."""
    return None


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"context", "verify", "warn"}:
        raise SystemExit(2)
    # Installed historical definitions may invoke these during transition.
    # Return before parsing stdin or inspecting user/Git state.
    if sys.argv[1] in {"verify", "warn"}:
        return
    value = payload(require_cwd=False)
    if value.get("hook_event_name") != "SessionStart":
        return
    context(value)


if __name__ == "__main__":
    main()
