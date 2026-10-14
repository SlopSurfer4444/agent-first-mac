"""Small explicit native wiring for the separately reviewed current doctor.

No work at import. No old readiness/model/apply route, arbitrary command, retry
or trust mutation. The doctor's real-tree/source guard owns source admission.
"""

import os
import pwd

from lib import vendor_compatibility_probe as probe
from lib import vendor_compatibility_policy as policy
from lib import vendor_fixture_custody as custody_policy


def custody_cli(doctor, slot=None):
    """Fixed private diagnostic slots; no vendor doctor or arbitrary path input."""
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    doctor.require(type(uid) is int and uid > 0 and doctor.D.R.integrations._path(home))
    scratch = home + "/AIDev/scratch"
    if slot is None:
        try:
            with custody_policy.Custody(scratch, home, uid, create=False,
                    envelope=probe.require_fixture_envelope) as custody:
                return custody.status()
        except custody_policy.CustodyError as error:
            if error.reason_class == "fixture_custody_absent":
                return {"scope": "disposable-vendor-fixture-custody", "outstanding": 0,
                        "slots": [], "maximumReservations": custody_policy.SLOTS,
                        "retainedByteAdmissionBudget": custody_policy.MAX_BYTES, "hardDiskQuota": False}
            raise
    doctor.require(type(slot) is int and 0 <= slot < custody_policy.SLOTS)
    result = []
    def retire(head, *, source_guard):
        del head
        source_guard()
        with custody_policy.Custody(scratch, home, uid, create=False,
                envelope=probe.require_fixture_envelope) as custody:
            result.append(custody.retire(slot))
        source_guard()
        return True
    # run's operation callback requires integrated accepted source, and stays
    # inside its held source checks. A Git-only gate avoids vendor-gate deadlock.
    admission = native(doctor, True, operation_check=retire)
    doctor.require(admission["verdict"] == "GIT_ONLY_VALID" and len(result) == 1)
    return result[0]


def native(doctor, git_only, *, capture=None, audit_history=False, operation_check=None,
           reviewed_target=False):
    doctor.require(type(git_only) is bool and (capture is None or callable(capture)))
    root, uid = str(doctor.ROOT), os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    doctor.require(type(uid) is int and uid > 0 and doctor.D.R.integrations._path(home)
                   and (operation_check is not None or os.getcwd() == root))
    readiness = doctor.D.R
    budget = readiness.Budget(seconds=180)
    # In-process custody, not a disk registry or cleanup authority. Keep prior
    # dispositions until the caller explicitly consumes their private owners.
    retained = getattr(doctor, "_vendor_fixture_dispositions", None)
    if retained is None:
        retained = []
        doctor._vendor_fixture_dispositions = retained
    doctor.require(type(retained) is list)

    def retain_fixture(disposition):
        doctor.require(type(disposition) is probe.FixtureDisposition)
        if not any(item is disposition for item in retained):
            retained.append(disposition)

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
        before = len(retained)
        try:
            value = probe.observe(root=root, home=home, uid=uid, budget=shared,
                source_guard=source_guard, readiness=readiness, process=doctor.D.process,
                policy=policy, fixture_consumer=retain_fixture)
        except BaseException as error:
            disposition = getattr(error, "private_fixture_disposition", None)
            if type(disposition) is probe.FixtureDisposition:
                retain_fixture(disposition)
            error.private_fixture_dispositions = tuple(retained[before:])
            error.retained_fixture_count = len(retained) - before
            raise
        value["retainedFixtureCount"] = len(retained) - before
        if len(retained) > before:
            value["privateFixtureDispositions"] = tuple(retained[before:])
        if capture is not None:
            capture(value)
        return value

    doctor.require(type(audit_history) is bool and type(reviewed_target) is bool
                   and not (audit_history and reviewed_target)
                   and (not reviewed_target or git_only))
    git = doctor.NativeGit(home, root, budget)
    if reviewed_target:
        current = git._tree(git._text("rev-parse", "--verify", "HEAD"))
        if doctor.current_sources.OWNER_FIRST_WAVE_PATH in current:
            prior = operation_check
            def operation_check(head, *, source_guard):
                source_guard()
                doctor.current_sources.reviewed_target(git, head, git._tree(head))
                return True if prior is None else prior(head, source_guard=source_guard)
        else:
            audit_history = True
    if audit_history:
        git.audit_history = True
    return doctor.run(git=git, budget=budget,
        source_factory=source_factory, canonical_main=root == home + "/AIDev/control",
        git_only=git_only, sentinel_check=None if git_only else sentinel,
        **({"operation_check": operation_check} if operation_check is not None else {}))
