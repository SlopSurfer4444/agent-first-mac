"""Pure operation dependencies and observations, without source/doctor imports."""
import re

DEPENDENCIES = {
    "nix-prepare": ("reviewed-target", "build-inputs"),
    "root-apply": ("reviewed-target", "root-contract", "built-target"),
    "wine-install": ("payload-owner", "wine-target", "recovery"),
    "wine-recovery": ("payload-owner", "recovery"),
    "ssh-holder": ("ssh-transport", "native-consent"),
    "shell-apply": ("payload-owner", "recovery"),
    "shell-recovery": ("payload-owner", "recovery"),
    "harness-disable": ("owned-target", "recovery"),
}


def require(value, reason):
    if value is not True:
        raise RuntimeError(reason)


def evaluate(operation, commit, *, checks, source_guard, target_guard):
    """True means observed, never owner authorization or native consent."""
    require(type(operation) is str and operation in DEPENDENCIES, "operation_unknown")
    require(type(commit) is str and commit != "0" * 40
            and re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "operation_commit")
    required = DEPENDENCIES[operation]
    require(type(checks) is dict and set(checks) == set(required)
            and all(callable(checks[key]) for key in required), "operation_dependencies")
    require(callable(source_guard) and callable(target_guard), "operation_guard")
    def guard():
        require(source_guard() is True, "operation_source_drift")
        require(target_guard() is True, "operation_target_drift")
    guard()
    for name in required:
        require(checks[name]() is True, "operation_dependency_" + name)
        guard()
    return {"schema": 1, "operation": operation, "commit": commit,
            "scopedCandidateReady": True, "observedDependencies": list(required),
            "liveGateSatisfied": False, "machineMutationAuthorized": False,
            "installedStateAccepted": False, "nativeConsentGranted": False}
