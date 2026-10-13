"""Small explicit native wiring for the separately reviewed current doctor.

No work at import. No old readiness/model/apply route, arbitrary command, retry
or trust mutation. The doctor's real-tree/source guard owns source admission.
"""

import os
import pwd

from lib import vendor_compatibility_probe as probe
from lib import vendor_compatibility_policy as policy


def native(doctor, git_only, *, capture=None, audit_history=False):
    doctor.require(type(git_only) is bool and (capture is None or callable(capture)))
    root, uid = str(doctor.ROOT), os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    doctor.require(type(uid) is int and uid > 0 and doctor.D.R.integrations._path(home)
                   and os.getcwd() == root)
    readiness = doctor.D.R
    budget = readiness.Budget(seconds=180)

    def source_factory(path, absent=False):
        cls = readiness.SourceFile
        item = cls.__new__(cls)
        probe.install_closer(item, "fds")
        try:
            cls.__init__(item, doctor.ROOT / path, home, uid, budget, absent=absent)
        except BaseException as original:
            selected = original
            errors = [original]
            try:
                item.close()
            except BaseException as error:
                errors.append(error)
                selected = probe.prefer(selected, error)
            selected.private_errors = tuple(errors)
            selected.retained_sources = tuple(owner for error in errors
                for owner in getattr(error, "retained_sources", ())) + (item,)
            selected.source_handles_closed = (item._sentinel_close_error is None
                and all(getattr(error, "source_handles_closed", True) is True for error in errors))
            raise selected from None
        return item

    def sentinel(shared, *, source_guard):
        value = probe.observe(root=root, home=home, uid=uid, budget=shared,
            source_guard=source_guard, readiness=readiness, process=doctor.D.process, policy=policy)
        if capture is not None:
            capture(value)
        return value

    doctor.require(type(audit_history) is bool)
    git = doctor.NativeGit(home, root, budget)
    if audit_history:
        git.audit_history = True
    return doctor.run(git=git, budget=budget,
        source_factory=source_factory, canonical_main=root == home + "/AIDev/control",
        git_only=git_only, sentinel_check=None if git_only else sentinel)
