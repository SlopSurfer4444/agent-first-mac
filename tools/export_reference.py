"""Fail-closed, committed-object-only reference export into a NEW scratch directory.

No installation, overlay, removal, network, source checkout reads or Git writes.
The scanner is a publication backstop, not a guarantee that arbitrary source is safe.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import unicodedata

MAX_BLOB = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
ALLOWLIST = Path(__file__).with_name("export-files.json")
OLD_FLOOR = '''        manifest = json.loads((ROOT / "manifests/phase5-trusted-probe.json").read_text())
        self.assertEqual(P.MINIMUM_VERSION, manifest["cli"]["observedVersion"])'''
NEW_FLOOR = '''        # Public export omits host observations; compare the two source constants.
        floor = next(node for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "MINIMUM_VERSION" for target in node.targets))
        self.assertEqual(P.MINIMUM_VERSION, ast.literal_eval(floor.value))'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(source, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}
    p = subprocess.run(["/usr/bin/git", "--no-replace-objects", "-C", str(source), *args],
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode:
        raise ValueError("Git object lookup failed")
    return p.stdout


def valid_path(name):
    if not isinstance(name, str) or not name or not name.isascii():
        raise ValueError("Invalid allowlist path")
    parts = name.split("/")
    if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
        raise ValueError("Unsafe path")
    if not re.fullmatch(r"[A-Za-z0-9_./+@-]+", name):
        raise ValueError("Unsafe path characters")
    allowed = (parts[0] in {"bin", "lib", "tests", "Sources", "vendor", "darwin", "payload"}
               and len(parts) > 1) or name in {
                   "Package.swift", "flake.nix", "flake.lock", "codex/hooks/phase5-contract.py"}
    if not allowed or name.startswith("tests/fixtures/"):
        raise ValueError("Path outside publication categories")


def sanitize(text, replacements):
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def load_redactions(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("Invalid private redactions file")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) - {"replacements", "denyTerms", "exceptions"} or not {"replacements", "denyTerms"} <= set(value):
        raise ValueError("Invalid redactions schema")
    pairs, deny, exceptions = value["replacements"], value["denyTerms"], value.get("exceptions", [])
    if not all(isinstance(v, list) and len(v) <= 256 for v in (pairs, deny, exceptions)):
        raise ValueError("Invalid redactions bounds")
    if any(not isinstance(p, list) or len(p) != 2 or any(not isinstance(s, str) or not 1 <= len(s) <= 256 or any(ord(c) < 32 for c in s) for s in p) for p in pairs):
        raise ValueError("Invalid replacement pair")
    if any(not isinstance(s, str) or not 1 <= len(s) <= 256 or any(ord(c) < 32 for c in s) for s in deny):
        raise ValueError("Invalid deny term")
    for item in exceptions:
        if not isinstance(item, dict) or set(item) != {"path", "literal", "class"}:
            raise ValueError("Invalid exact exception")
        valid_path(item["path"])
        if item["class"] not in {"public-standard", "synthetic-fixture", "public-version", "negative-test"}:
            raise ValueError("Unknown exception class")
        literal = item["literal"]
        if not isinstance(literal, str) or not 1 <= len(literal) <= 256 or any(ord(c) < 32 for c in literal):
            raise ValueError("Invalid exception literal")
    return value, digest(raw)


def scan(text):
    # Never redact a discovered credential and continue publishing.
    patterns = [r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
                r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b",
                r"(?i)\b(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*[\"']([^\"'\n]{12,})[\"']",
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"]
    if any(re.search(pattern, text) for pattern in patterns):
        raise ValueError("Publication scanner rejected sensitive-looking content")
    # Named false positives: reserved example email domains, loopback/unspecified
    # IPv4 and RFC 5737 documentation blocks. No blanket test-file exemption.
    for email in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        domain = email.rsplit("@", 1)[1].lower()
        if domain not in {"example.com", "example.org", "example.net", "example.test"} and not domain.endswith(".invalid"):
            raise ValueError("Non-example email")
    for value in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            continue
        if not (address.is_loopback or address.is_unspecified or any(address in ipaddress.ip_network(n)
                for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))):
            raise ValueError("Non-example IPv4 address")


def export(source, commit, destination, redactions, allowlist=ALLOWLIST):
    rules, rules_digest = load_redactions(redactions)
    source, destination = Path(source), Path(destination)
    if not source.is_absolute() or not source.is_dir() or not destination.is_absolute():
        raise ValueError("Absolute source repository and destination required")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Full lowercase commit ID required")
    # Scratch-only output: even an accidental live destination cannot be accepted.
    parent = destination.parent.resolve(strict=True)
    scratch = (Path("/private/tmp").resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(parent == p or p in parent.parents for p in scratch):
        raise ValueError("Destination must be a fresh scratch child")
    if destination.name in {"", ".", ".."} or os.path.lexists(destination):
        raise ValueError("Destination must not exist")
    if git(source, "cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("Expected commit object")
    raw_allowlist = Path(allowlist).read_bytes()
    names = json.loads(raw_allowlist)
    if not isinstance(names, list) or not names or len(names) > 4000:
        raise ValueError("Expected bounded nonempty explicit allowlist")
    for name in names:
        valid_path(name)
    if len(set(names)) != len(names):
        raise ValueError("Duplicate allowlist path")
    entries = {}
    for entry in git(source, "ls-tree", "-rz", commit).split(b"\0"):
        if entry:
            meta, path = entry.split(b"\t", 1)
            entries[path.decode("utf-8")] = meta.decode("ascii").split()
    outputs, keys, total = {}, set(), 0
    public_sources = {}
    for original in entries:
        public = sanitize(original, rules["replacements"])
        if public in names:
            valid_path(original)
            if public in public_sources:
                raise ValueError("Source-to-public path collision")
            public_sources[public] = original
    for name in sorted(names):
        original = public_sources.get(name)
        mode, kind, oid = entries.get(original, (None, None, None))
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("Missing, symlink, submodule or unsupported object")
        size = int(git(source, "cat-file", "-s", oid))
        total += size
        if size > MAX_BLOB or total > MAX_TOTAL:
            raise ValueError("Export size bound exceeded")
        raw = git(source, "cat-file", "blob", oid)
        text = raw.decode("utf-8")
        if "\0" in text:
            raise ValueError("Binary content")
        target = name
        valid_path(target)
        key = unicodedata.normalize("NFC", target).casefold()
        if key in keys or any(key.startswith(k + "/") or k.startswith(key + "/") for k in keys):
            raise ValueError("Sanitized path collision")
        keys.add(key)
        if not name.startswith("vendor/"):
            text = sanitize(text, rules["replacements"])
        if name == "tests/test_vendor_compatibility_policy.py":
            old_name = "test_version_equivalent_to_accepted_comparator_and_manifest_floor"
            if text.count(OLD_FLOOR) != 1 or text.count(old_name) != 1:
                raise ValueError("Known public test transform drifted")
            text = text.replace(OLD_FLOOR, NEW_FLOOR).replace(old_name, "test_version_equivalent_to_source_comparator_and_source_floor")
        try:
            if any(term.casefold() in (target + "\n" + text).casefold() for term in rules["denyTerms"]):
                raise ValueError("Private deny term remains")
            scan_text = text
            for item in rules.get("exceptions", []):
                if item["path"] == name:
                    if item["literal"] not in scan_text:
                        raise ValueError("Exact exception drifted")
                    scan_text = scan_text.replace(item["literal"], "PUBLIC_REVIEWED_LITERAL")
            scan(scan_text)
        except ValueError as error:
            raise ValueError(target + ": " + str(error)) from None
        outputs["reference/" + target] = text.encode("utf-8")
    provenance = {"sourceCommit": commit, "allowlistDigest": digest(raw_allowlist), "redactionsDigest": rules_digest,
                  "outputHashes": {p: digest(b) for p, b in sorted(outputs.items())}}
    outputs["export-provenance.json"] = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()
    # All validation precedes creation. Exclusive creation; no overlay or cleanup.
    destination = parent / destination.name
    destination.mkdir(mode=0o700)
    for name, raw in sorted(outputs.items()):
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            os.fchmod(handle.fileno(), 0o644)
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--redactions", required=True, help="Absolute private reviewed redaction/exception JSON")
    args = parser.parse_args()
    try:
        result = export(args.source, args.commit, args.destination, args.redactions)
    except UnicodeError:
        parser.exit(1, "Export refused: non-UTF-8 object (content withheld).\n")
    except ValueError as error:
        parser.exit(1, "Export refused: " + str(error) + "\n")
    except (OSError, UnicodeError, subprocess.SubprocessError):
        parser.exit(1, "Export refused; object, encoding or filesystem failure (content withheld).\n")
    print(json.dumps({"sourceCommit": result["sourceCommit"], "exportedFiles": len(result["outputHashes"])}))


if __name__ == "__main__":
    main()
