"""Committed user-helper inputs, not a root grant or Git reviewer genealogy.

Call only from a trusted, owner-authorized lifecycle. Source paths do not grant
trust. Static imports (including deferred imports), literal local helper/data
references and explicit dynamic inputs form the conservative closure. Native
consent, target ownership, recovery and root-target review remain separate.
"""
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class SourceError(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise SourceError(reason)


def git(root, *args):
    need(os.getuid() != 0, "user_source_must_not_run_as_root")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run(["/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", *args], cwd=root, env=env,
        capture_output=True, timeout=10, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 16 * 1024 * 1024,
         "source_git_observation_failed")
    return result.stdout


def snapshot(root, revision=None):
    need(revision is None or type(revision) is str and re.fullmatch("[0-9a-f]{40}", revision)
         and revision != "0" * 40, "source_commit_mismatch")
    head = git(root, "rev-parse", "--verify", "HEAD" if revision is None else revision + "^{commit}").decode("ascii").strip()
    need(re.fullmatch("[0-9a-f]{40}", head), "source_commit_invalid")
    rows = {}
    for record in git(root, "ls-tree", "-rz", "--full-tree", head).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        need(not path.startswith("/") and all(p not in ("", ".", "..") for p in path.split("/")),
             "source_path_invalid")
        rows[path] = (mode, kind, oid)
    return head, rows


def _blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class Held:
    """No-follow descriptor holding; every named parent/leaf is rechecked."""
    def __init__(self, root, path, expected):
        self.fds, self.links = [], []
        self.path, self.expected = path, expected
        try:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(fd)
            self.root, self.root_stamp = Path(root), self.stamp(os.fstat(fd))
            need(self.root_stamp[2] == os.getuid() and not self.root_stamp[3] & 0o022,
                 "source_root_owner")
            parts = path.split("/")
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                self.fds.append(child)
                facts = os.fstat(child)
                need(facts.st_uid == os.getuid() and not facts.st_mode & 0o022, "source_parent_owner")
                self.links.append((fd, part, self.stamp(facts)))
                fd = child
            self.parent, self.leaf = fd, parts[-1]
            self.fd = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            self.fds.append(self.fd)
            facts = os.fstat(self.fd)
            need(stat.S_ISREG(facts.st_mode) and facts.st_uid == os.getuid()
                 and not facts.st_mode & 0o022 and facts.st_nlink == 1
                 and facts.st_size <= 8 * 1024 * 1024, "source_file_unsafe")
            self.file_stamp = self.stamp(facts)
            self.data = os.pread(self.fd, facts.st_size + 1, 0)
            need(expected[:2] in (("100644", "blob"), ("100755", "blob"))
                 and bool(facts.st_mode & 0o111) == (expected[0] == "100755")
                 and _blob(self.data) == expected[2], "affected_source_uncommitted")
            self.verify()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def stamp(facts):
        return facts.st_dev, facts.st_ino, facts.st_uid, facts.st_mode

    def verify(self):
        need(self.stamp(os.stat(self.root, follow_symlinks=False)) == self.root_stamp, "source_root_drift")
        for parent, name, stamp in self.links:
            need(self.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp, "source_parent_drift")
        facts = os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)
        need(self.stamp(facts) == self.file_stamp == self.stamp(os.fstat(self.fd))
             and facts.st_nlink == 1 and os.fstat(self.fd).st_nlink == 1
             and facts.st_size == len(self.data)
             and os.pread(self.fd, len(self.data) + 1, 0) == self.data, "affected_source_drift")
        return True

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []


def callable_paths(root, callbacks):
    paths = set()
    for callback in callbacks:
        path = inspect.getsourcefile(callback)
        if path is not None:
            candidate = Path(path).absolute()
            if candidate.is_relative_to(root):
                paths.add(candidate.relative_to(root).as_posix())
    return paths


def run(control, callback, *, entrypoints=(), extra_paths=(), expected_commit=None):
    """Hold the actual affected closure around callback(head, source_guard=...).

    A helper with computed runtime input paths supplies extra_paths from its
    existing manifest. This is data ownership, not a new central registration.
    Unrelated dirty files, notes, commits and historical receipt count do not
    veto this user-level route. Exact required code/data must be committed.
    """
    root = Path(control)
    need(sys.dont_write_bytecode and sys.pycache_prefix == "/dev/null", "source_cache_bypass_required")
    need(root.is_absolute() and root == root.resolve(strict=True), "source_root_invalid")
    head, tree = snapshot(root, expected_commit)
    need(expected_commit is None or expected_commit == head, "source_commit_mismatch")
    pending = (set(entrypoints) | set(extra_paths) | callable_paths(root, (callback,))
               | {Path(__file__).relative_to(root).as_posix()})
    need(bool(pending) and all(type(p) is str and p in tree for p in pending), "source_entry_untracked")
    held, absent, import_stems = {}, set(), set()
    data_only, discovered = set(), set()
    basenames = {}
    for path in tree:
        if path.startswith(("bin/", "lib/", "manifests/")):
            basenames.setdefault(Path(path).name, set()).add(path)

    def module(name):
        base = name.replace(".", "/")
        if not base or not all(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", p) for p in base.split("/")):
            return False
        candidates = (base + ".py", base + "/__init__.py")
        # Both module and package candidates matter: Python may prefer a
        # newly introduced package or native module to the committed .py file.
        for prefix in ("", "bin/", "lib/"):
            for index in range(1, len(base.split("/")) + 1):
                stem = prefix + "/".join(base.split("/")[:index])
                import_stems.add(stem)
                for candidate in (stem + ".py", stem + "/__init__.py"):
                    if candidate in tree: pending.add(candidate)
                    else: absent.add(candidate)
        found = [p for p in candidates if p in tree]
        if found:
            pending.update(found)
            for index in range(1, len(base.split("/"))):
                initializer = "/".join(base.split("/")[:index]) + "/__init__.py"
                if initializer in tree: pending.add(initializer)
                else: absent.add(initializer)
        else:
            # Prevent untracked modules/packages from shadowing stdlib imports
            # on either local interpreter search-path entry.
            for prefix in ("", "bin/"):
                absent.update(prefix + p for p in candidates)
        return bool(found)

    def discover(path, raw):
        if path.endswith(".json"):
            # Existing manifests declare computed helper paths as string data;
            # include local tracked references recursively without executing it.
            try: value = json.loads(raw)
            except (ValueError, UnicodeError): return
            def visit(value):
                if type(value) is str and value in tree: pending.add(value)
                elif type(value) is list:
                    for item in value: visit(item)
                elif type(value) is dict:
                    for key, item in value.items(): visit(key); visit(item)
            visit(value)
            return
        if not (path.endswith(".py") or path.startswith("bin/") and b"python" in raw.split(b"\n", 1)[0]):
            return
        try: parsed = ast.parse(raw)
        except (SyntaxError, UnicodeError): raise SourceError("source_python_invalid") from None
        # Explicit source-as-data declarations retain exact bytes without
        # treating historical proof inputs as executed modules. Any actual
        # import/reference elsewhere promotes that path to normal discovery.
        opaque_nodes = set()
        for declaration in ast.walk(parsed):
            if (isinstance(declaration, ast.AnnAssign)
                    and isinstance(declaration.annotation, ast.Constant)
                    and declaration.annotation.value == "source-data-only"):
                need(isinstance(declaration.value, (ast.Tuple, ast.List, ast.Set, ast.Constant)), "source_data_declaration_invalid")
                values = (declaration.value,) if isinstance(declaration.value, ast.Constant) else declaration.value.elts
                for item in values:
                    need(isinstance(item, (ast.Name, ast.Constant)), "source_data_declaration_invalid")
                    if isinstance(item, ast.Constant):
                        need(type(item.value) is str and item.value in tree, "source_data_declaration_invalid")
                        data_only.add(item.value)
                        opaque_nodes.add(item)
        for node in ast.walk(parsed):
            if node in opaque_nodes: continue
            if isinstance(node, ast.Import):
                for alias in node.names: module(alias.name)
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                if node.level:
                    parent = path.split("/")[:-node.level]
                    prefix = ".".join(parent + ([prefix] if prefix else []))
                module(prefix)
                for alias in node.names:
                    if alias.name != "*": module(prefix + "." + alias.name)
            elif isinstance(node, ast.Constant) and type(node.value) is str:
                value = node.value
                if value in tree: pending.add(value)
                elif value in basenames and ("-" in value or "." in value):
                    pending.update(basenames[value])
                elif value.startswith(("lib.", "vendor.")):
                    module(value)

    def guard():
        need(sys.dont_write_bytecode and sys.pycache_prefix == "/dev/null", "source_cache_bypass_required")
        for item in held.values(): item.verify()
        for path in absent - held.keys():
            need(not os.path.lexists(root / path), "source_import_shadow")
        for stem in import_stems:
            path = root / stem
            for directory, name in ((path.parent, path.name), (path, "__init__")):
                if not directory.is_dir(): continue
                with os.scandir(directory) as entries:
                    for entry in entries:
                        suffix = entry.name[len(name):] if entry.name.startswith(name + ".") else ""
                        need(not (suffix in (".pyc", ".pyo") or suffix.endswith((".so", ".dylib", ".pyd"))),
                             "source_import_shadow")
        return True

    def committed_guard():
        # Only entry/closure observe committed identity. Publication guards
        # use the actual held code/data, not another Git subprocess round.
        _, current = snapshot(root)
        need(all(current.get(path) == tree[path] for path in held), "affected_source_commit_drift")

    try:
        while (pending - discovered) or (data_only - held.keys()):
            path = sorted((pending - discovered) | (data_only - held.keys()))[0]
            need(path in tree and len(held) < 1024, "source_closure_invalid")
            if path not in held: held[path] = Held(root, path, tree[path])
            if path in pending:
                discovered.add(path)
                discover(path, held[path].data)
        guard()
        if expected_commit is not None:
            committed_guard()
        value = callback(head, source_guard=guard)
        guard()
        committed_guard()
        return value
    finally:
        for item in reversed(list(held.values())): item.close()


def check(control, commit, *, entrypoints, extra_paths=()):
    """Recheck the same component inputs; unrelated HEAD advancement is fine."""
    return run(control, lambda head, source_guard: source_guard(),
               entrypoints=entrypoints, extra_paths=extra_paths, expected_commit=commit)
