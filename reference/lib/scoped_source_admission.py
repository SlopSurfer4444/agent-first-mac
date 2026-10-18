"""Committed user-helper inputs, not a root grant or Git reviewer genealogy.

Call only from a trusted, owner-authorized lifecycle. Source paths do not grant
trust. Static imports (including deferred imports), literal local helper/data
references and explicit dynamic inputs form the conservative closure. Native
consent, target ownership, recovery and root-target review remain separate.
"""
import ast
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import inspect
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import types

_ACTIVE = ContextVar("affected_source_context", default=None)
_EXECUTION = ContextVar("affected_source_execution", default=None)
_AUDIT_INSTALLED = False
_WINDOW = None
_AUDIT_PROBE = None

SOURCE_REASONS = frozenset({
    "user_source_must_not_run_as_root", "source_git_observation_failed",
    "source_commit_mismatch", "source_commit_invalid", "source_path_invalid",
    "source_root_owner", "source_parent_owner", "source_file_unsafe",
    "affected_source_uncommitted", "source_root_drift", "source_parent_drift",
    "affected_source_drift", "source_cache_bypass_required", "source_root_invalid",
    "source_entry_untracked", "source_python_invalid", "source_data_declaration_invalid",
    "source_import_shadow", "affected_source_commit_drift", "source_closure_invalid",
    "source_context_scope", "source_execution_unbound", "source_execution_drift",
})


def public_failure(error):
    """Closed, path-free refusal details; never publish arbitrary exceptions."""
    reason = str(error) if isinstance(error, SourceError) else "source_admission_failed"
    if reason not in SOURCE_REASONS:
        reason = "source_admission_failed"
    action = ("restart_helper_from_committed_source" if reason in
              {"source_execution_unbound", "source_execution_drift"} else
              "review_affected_source_and_retry")
    return {"reason": reason, "affectedScope": "affected-user-helper-source",
            "nextAction": action}


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


@contextmanager
def admitted_source(control, *, entrypoints=(), extra_paths=(), data_paths=None, opaque_paths=(), expected_commit=None):
    """Hold one affected closure across observation and publication.

    A helper with computed runtime input paths supplies extra_paths from its
    existing manifest. This is data ownership, not a new central registration.
    Unrelated dirty files, notes, commits and historical receipt count do not
    veto this user-level route. Exact required code/data must be committed.
    data_paths, when supplied, declares the adapter-selected data inputs instead
    of guessing data dependencies from every Python string. Their committed JSON
    references are still followed. Imported/executable inputs remain discovered.
    opaque_paths are hash/comparison inputs, the dynamic equivalent of a
    source-data-only annotation. Actual imports promote them to executable code.
    """
    root = Path(control)
    need(sys.dont_write_bytecode and sys.pycache_prefix == "/dev/null", "source_cache_bypass_required")
    need(root.is_absolute() and root == root.resolve(strict=True), "source_root_invalid")
    active = _ACTIVE.get()
    requested = set(entrypoints) | set(extra_paths) | set(data_paths or ())
    opaque = set(opaque_paths)
    if active is not None:
        active_root, head, paths, guard, extend, _ = active
        need(root == active_root, "source_context_scope")
        need(expected_commit is None or expected_commit == head, "source_commit_mismatch")
        extend(requested, opaque, data_paths is None)
        guard()
        yield head, guard
        guard()
        return
    head, tree = snapshot(root, expected_commit)
    need(expected_commit is None or expected_commit == head, "source_commit_mismatch")
    pending = (requested
               | {Path(__file__).relative_to(root).as_posix()})
    need(bool(pending) and all(type(p) is str and p in tree for p in pending | opaque), "source_entry_untracked")
    held, absent, import_stems = {}, set(), set()
    data_only, discovered = opaque, set()
    discover_data = data_paths is None
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
        bindings = {}
        for node in ast.walk(parsed):
            name = None
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store): name = node.id
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): name = node.name
            elif isinstance(node, ast.alias): name = node.asname or node.name.split('.')[0]
            elif isinstance(node, ast.ExceptHandler): name = node.name
            if name is not None: bindings[name] = bindings.get(name, 0) + 1
        constants = {}
        for declaration in parsed.body:
            if isinstance(declaration, ast.Assign):
                for target in declaration.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = (declaration.value if bindings[target.id] == 1
                                                and target.id not in constants
                                                and isinstance(declaration.value, ast.Constant) else None)
        loaded_names = {node.id for node in ast.walk(parsed)
                        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        unused_nodes = set()
        for declaration in ast.walk(parsed):
            if (isinstance(declaration, ast.Assign) and isinstance(declaration.value, ast.Constant)
                    and all(isinstance(t, ast.Name) and t.id not in loaded_names for t in declaration.targets)):
                unused_nodes.add(declaration.value)
            elif isinstance(declaration, ast.Expr) and isinstance(declaration.value, ast.Constant):
                unused_nodes.add(declaration.value)
        for declaration in ast.walk(parsed):
            if (isinstance(declaration, ast.AnnAssign)
                    and isinstance(declaration.annotation, ast.Constant)
                    and declaration.annotation.value == "source-data-only"):
                need(isinstance(declaration.value, (ast.Tuple, ast.List, ast.Set, ast.Constant)), "source_data_declaration_invalid")
                values = (declaration.value,) if isinstance(declaration.value, ast.Constant) else declaration.value.elts
                for item in values:
                    if isinstance(item, ast.Name):
                        item = constants.get(item.id)
                        need(declaration in parsed.body and isinstance(item, ast.Constant)
                             and item.lineno < declaration.lineno, "source_data_declaration_invalid")
                    need(isinstance(item, ast.Constant) and type(item.value) is str
                         and item.value in tree, "source_data_declaration_invalid")
                    data_only.add(item.value)
                    opaque_nodes.add(item)
        for node in ast.walk(parsed):
            if node in opaque_nodes or node in unused_nodes: continue
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
                def selected(candidate):
                    return discover_data or candidate.endswith('.py') or candidate.startswith('bin/')
                if value in tree and selected(value): pending.add(value)
                elif value in basenames and ("-" in value or "." in value):
                    pending.update(p for p in basenames[value] if selected(p))
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

    def extend(paths, opaque, implicit):
        nonlocal discover_data
        need(all(type(p) is str and p in tree for p in paths | opaque), "source_entry_untracked")
        pending.update(paths)
        data_only.update(opaque)
        if implicit and not discover_data:
            discover_data = True
            discovered.clear()
        while (pending - discovered) or (data_only - held.keys()):
            path = sorted((pending - discovered) | (data_only - held.keys()))[0]
            need(path in tree and len(held) < 1024, "source_closure_invalid")
            if path not in held: held[path] = Held(root, path, tree[path])
            if path in pending:
                discovered.add(path)
                discover(path, held[path].data)
        guard()
        if _WINDOW is not None:
            _compile_held(root, held, _WINDOW['expected'], discovered)

    try:
        extend(set(), set(), discover_data)
        if expected_commit is not None:
            committed_guard()
        token = _ACTIVE.set((root, head, held, guard, extend, discovered))
        try:
            yield head, guard
            guard()
            committed_guard()
        finally:
            _ACTIVE.reset(token)
    finally:
        for item in reversed(list(held.values())): item.close()


def run(control, callback, *, entrypoints=(), extra_paths=(), data_paths=None, opaque_paths=(), expected_commit=None):
    """Hold inputs; an in-tree lifecycle callback must have bound execution.

    External fixture callbacks can inspect held inputs, but this API does not
    attest their execution version or confer authority on external Python.
    """
    callbacks = callable_paths(Path(control), (callback,))
    if callbacks - {Path(__file__).relative_to(control).as_posix()}:
        require_execution(control)
    paths = set(entrypoints) | callbacks
    with admitted_source(control, entrypoints=paths, extra_paths=extra_paths,
                         data_paths=data_paths, opaque_paths=opaque_paths, expected_commit=expected_commit) as (head, guard):
        return callback(head, source_guard=guard)


def observe(root, *, full=False, operation_check=None, extra_paths=()):
    """User-delivery facade without maintenance, vendor, or root imports."""
    need(Path(root) == Path(pwd.getpwuid(os.getuid()).pw_dir) / "AIDev/control" and Path(root).resolve() == Path(root),
         "source_root_invalid")
    need(full is False, "source_context_scope")
    require_execution(root)
    result = {}
    def callback(head, *, source_guard):
        need((operation_check(head, source_guard=source_guard) if operation_check else source_guard()) is True,
             "source_context_scope")
        result.update(scope="affected-user-helper-source", verdict="SOURCE_VALID",
                      commit=head, rootAuthorityGranted=False)
        return True
    entries = callable_paths(Path(root), (operation_check,)) if operation_check else ()
    # Delivery inputs are copied/hashed, not programs or dependency manifests.
    # The adapter supplies its actual selected inputs, including nested data.
    with admitted_source(root, entrypoints=set(entries) | callable_paths(Path(root), (callback,)),
                         data_paths=(), opaque_paths=extra_paths) as (head, guard):
        callback(head, source_guard=guard)
    return result


def check(control, commit, *, entrypoints, extra_paths=(), data_paths=None, opaque_paths=()):
    """Recheck the same component inputs; unrelated HEAD advancement is fine."""
    require_execution(control)
    return run(control, lambda head, source_guard: source_guard(),
               entrypoints=entrypoints, extra_paths=extra_paths, data_paths=data_paths,
               opaque_paths=opaque_paths, expected_commit=commit)


def _inside(root, filename):
    return (type(filename) is str and os.path.isabs(filename)
            and Path(filename).is_relative_to(root))


def _audit_exec(event, args):
    """A cooperative import-window check, not a Python security sandbox."""
    global _AUDIT_PROBE
    if event == 'control.source.audit-probe' and args == (_AUDIT_PROBE,):
        _AUDIT_PROBE = True
        return
    state = _WINDOW
    if event != "exec" or state is None:
        return
    root, expected, guard = state['root'], state['expected'], state['guard']
    code = args[0]
    if _inside(root, code.co_filename):
        try:
            guard()
            candidates = expected.get(code.co_filename, ())
            need(any(code == candidate for candidate in candidates), "source_execution_drift")
        except BaseException:
            state['failed'] = True
            raise


def require_execution(control):
    """Live adapters require fresh, bound entrypoint execution before effects."""
    need(_WINDOW is not None and _WINDOW['root'] == Path(control)
         and _ACTIVE.get() is not None and not _WINDOW['failed'], "source_execution_unbound")
    return _WINDOW['guard']()


def _compile_held(root, held, expected, discovered):
    def code_tree(code):
        return [code] + [nested for value in code.co_consts if isinstance(value, types.CodeType)
                         for nested in code_tree(value)]
    for path in discovered:
        item = held[path]
        filename = str(root / path)
        if filename not in expected and (path.endswith('.py') or path.startswith('bin/') and b'python' in item.data.split(b'\n', 1)[0]):
            expected[filename] = code_tree(compile(item.data, filename, 'exec', dont_inherit=True))


def execute_entrypoint(control, entrypoint, *, expected_commit=None, extra_paths=(), opaque_paths=()):
    """Execute held entry bytes and compare ordinary local import code objects.

    The selected verifier is the trusted bootstrap. Call in a fresh interpreter
    before importing payload modules, not as a retroactive callback certificate.
    Nonlocal interpreter/stdlib/native dependencies are outside this claim.
    Dynamic execution deliberately disguised as external code is also outside
    this reviewed-caller contract; this is not a sandbox for arbitrary Python.
    """
    global _AUDIT_INSTALLED, _WINDOW, _AUDIT_PROBE
    root = Path(control)
    need(_EXECUTION.get() is None and _ACTIVE.get() is None, "source_execution_unbound")
    need(len(sys._current_frames()) == 1, "source_execution_unbound")
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if _inside(root, filename):
            need(filename == __file__ and getattr(module, "execute_entrypoint", None) is execute_entrypoint,
                 "source_execution_unbound")
    if not _AUDIT_INSTALLED:
        sys.addaudithook(_audit_exec)
        _AUDIT_PROBE = object()
        sys.audit('control.source.audit-probe', _AUDIT_PROBE)
        need(_AUDIT_PROBE is True, "source_execution_unbound")
        _AUDIT_INSTALLED = True
    with admitted_source(root, entrypoints=(entrypoint,), extra_paths=extra_paths,
                         data_paths=(), opaque_paths=opaque_paths, expected_commit=expected_commit) as (_, guard):
        held = _ACTIVE.get()[2]
        expected = {}
        _compile_held(root, held, expected, _ACTIVE.get()[5])
        filename = str(root / entrypoint)
        need(filename in expected, "source_execution_unbound")
        main = types.ModuleType('__main__')
        main.__file__, main.__package__, main.__spec__ = filename, None, None
        main.__dict__['__source_bound__'] = True
        previous_main, previous_argv = sys.modules.get('__main__'), sys.argv[:]
        sys.modules['__main__'] = main
        sys.argv[0] = filename
        _WINDOW = dict(root=root, expected=expected, guard=guard, failed=False)
        token = _EXECUTION.set(_WINDOW)
        stopped = None
        try:
            exec(expected[filename][0], main.__dict__)
        except SystemExit as error:
            stopped = error
        finally:
            try:
                guard()
                need(not _WINDOW['failed'], "source_execution_drift")
                need(len(sys._current_frames()) == 1, "source_execution_unbound")
            finally:
                _WINDOW = None
                _EXECUTION.reset(token)
                if previous_main is None: sys.modules.pop('__main__', None)
                else: sys.modules['__main__'] = previous_main
                sys.argv[:] = previous_argv
    if stopped is not None:
        raise stopped


_BOOTSTRAP = r'''
import json, os, pathlib, re, subprocess, sys, types
sys.dont_write_bytecode = True
sys.pycache_prefix = '/dev/null'
def git(*args):
    result = subprocess.run(['/usr/bin/git','--no-pager','-c','core.fsmonitor=false',
        '-c','core.hooksPath=/dev/null', *args], cwd=root, env=env,
        capture_output=True, timeout=10, check=False)
    if result.returncode or len(result.stdout) > 8*1024*1024:
        raise RuntimeError('source_bootstrap_unavailable')
    return result.stdout
report_failure = None
try:
    root, entry = pathlib.Path(sys.argv[1]), sys.argv[2]
    data_paths = json.loads(sys.argv[3])
    sys.argv = [str(root / entry), *sys.argv[4:]]
    env = {'PATH':'/usr/bin:/bin', 'HOME':str(pathlib.Path.home()), 'LC_ALL':'C',
           'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null',
           'GIT_OPTIONAL_LOCKS':'0', 'GIT_TERMINAL_PROMPT':'0'}
    head = git('rev-parse','--verify','HEAD').decode('ascii').strip()
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise RuntimeError('source_commit_invalid')
    path = root/'lib/scoped_source_admission.py'
    raw = git('show', head + ':lib/scoped_source_admission.py')
    module = types.ModuleType('lib.scoped_source_admission')
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    report_failure = module.public_failure
    sys.path.insert(0, str(root))
    module.execute_entrypoint(root, entry, expected_commit=head, opaque_paths=data_paths)
except Exception as error:
    # Git selection and verifier loading can fail before a source reporter exists.
    # Do not import any repository code or expose exception/path text to recover.
    failure = (report_failure(error) if report_failure is not None else
               {'reason': 'source_admission_failed',
                'affectedScope': 'affected-user-helper-source',
                'nextAction': 'review_affected_source_and_retry'})
    print(json.dumps(dict(verdict='BLOCKED', **failure), sort_keys=True))
    raise SystemExit(1)
'''


def reexec_entrypoint(path, *, data_paths=()):
    """Discard loaded payload state; choose source before fresh local imports."""
    entry = Path(path).absolute()
    root = entry.parent.parent
    need(entry.parent.name == 'bin' and root == root.resolve(strict=True), "source_root_invalid")
    os.execv(sys.executable, [sys.executable, '-I', '-S', '-B', '-c', _BOOTSTRAP,
                             str(root), 'bin/' + entry.name, json.dumps(list(data_paths)), *sys.argv[1:]])


if __name__ == '__main__':
    # First-stage callers reach this file through builtin posix.execv, with
    # -I -S -B already active, never by importing a writable lib package.
    try:
        entry, raw_inputs = sys.argv[1:3]
        sys.argv = [entry, *sys.argv[3:]]
        reexec_entrypoint(entry, data_paths=json.loads(raw_inputs))
    except Exception as error:
        print(json.dumps(dict(verdict='BLOCKED', **public_failure(error)), sort_keys=True))
        raise SystemExit(1)
