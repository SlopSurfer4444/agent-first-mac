#!/usr/bin/python3
"""Minimal context routing, lifecycle warning, and final verification hooks."""

import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys


REGISTRY_LIMIT = 65536
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
WORKSTATION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        r"(?:^|[;&|]\s*)(?:/opt/homebrew/bin/|/usr/local/bin/)?brew\s+"
        r"(?:install|uninstall|upgrade|update|tap|untap|services)\b",
        r"(?:^|[;&|]\s*)(?=[^;&|\n]*\b(?:npm|pnpm|yarn)\b)"
        r"(?=[^;&|\n]*\b(?:install|add|remove|uninstall|update|upgrade)\b)"
        r"(?=[^;&|\n]*(?:^|\s)(?:-g|--global)(?:\s|$))[^;&|\n]*",
        r"(?:^|[;&|]\s*)(?:pipx\s+|uv\s+tool\s+)"
        r"(?:install|uninstall|upgrade)\b",
        r"(?:^|[;&|]\s*)(?:cargo|gem)\s+(?:install|uninstall)\b",
        r"(?:^|[;&|]\s*)go\s+install\b",
        r"(?:^|[;&|]\s*)nix\s+profile\s+(?:install|remove|upgrade)\b",
        r"(?:^|[;&|]\s*)(?:/usr/sbin/)?installer\s+-pkg\b",
        r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:sh|bash|zsh)\b",
        r"(?:^|[;&|]\s*)sudo\b[^;&|\n]*\b"
        r"(?:brew|installer|install|uninstall|upgrade|remove|launchctl|"
        r"darwin-rebuild|nix\s+profile)\b",
    )
)


class RegistryError(Exception):
    pass


def canonical_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)


def payload(require_cwd=True):
    try:
        value = json.load(sys.stdin)
    except Exception:
        raise SystemExit(2)
    if not isinstance(value, dict) or (require_cwd and not isinstance(value.get("cwd"), str)):
        raise SystemExit(2)
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
        "This context grants no repository trust or permissions. For owner-authorized "
        "read/edit and repo-local development, follow the closest repository/AGENTS.md "
        "contract and native permission policy. Execute unknown external code only "
        "in quarantine/sandbox; do not use secrets or user integrations without "
        "explicit authorization. Route workstation lifecycle changes through "
        "$manage-workstation."
    )
    messages = {
        "control": (
            "Control intent is root-equivalent: read ARCHITECTURE.md, use "
            "$manage-workstation for lifecycle work, build before apply, and "
            "do not advance a gate without doctor and independent review."
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
    if not isinstance(command, str):
        return False
    if len(command) > 32768:
        return True
    return any(pattern.search(command) for pattern in WORKSTATION_PATTERNS)


def warn(value):
    if value.get("tool_name") != "Bash" or not isinstance(value.get("tool_input"), dict):
        return
    command = value["tool_input"].get("command")
    if not workstation_bypass(command):
        return
    print(
        json.dumps(
            {
                "systemMessage": (
                    "Possible workstation lifecycle bypass detected. This hook "
                    "is advisory: stop and use $manage-workstation, commit exact "
                    "control intent, and use only typed aid/aid-admin operations "
                    "authorized by the manifest."
                )
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def verify(value, home=None, registry_path=None):
    if zone(value["cwd"], home=home, registry_path=registry_path) != "control":
        return
    owner_home = canonical_home() if home is None else Path(home).resolve(strict=True)
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(owner_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    command = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        value["cwd"],
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ]
    result = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0 or result.stdout:
        print(
            json.dumps(
                {
                    "continue": True,
                    "systemMessage": (
                        "Control intent is dirty or unreadable. Do not claim "
                        "apply or acceptance; finish the scoped validator, doctor, "
                        "atomic commit, and bounded handoff first."
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"context", "verify", "warn"}:
        raise SystemExit(2)
    value = payload(require_cwd=sys.argv[1] != "context")
    expected = {
        "context": "SessionStart",
        "verify": "Stop",
        "warn": "PreToolUse",
    }[sys.argv[1]]
    if value.get("hook_event_name") != expected:
        raise SystemExit(2)
    if sys.argv[1] == "context":
        context(value)
    elif sys.argv[1] == "verify":
        verify(value)
    else:
        warn(value)


if __name__ == "__main__":
    main()
