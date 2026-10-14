"""Targeted ownership observations. Discovery is neither desired state nor trust.

Only declared collision identifiers escape; unrelated inventory stays in memory.
The runner receives argv and returns CompletedProcess-like returncode/stdout/stderr.
"""

import re
import subprocess
import os
import stat
import json
import hashlib
from pathlib import Path


MAX_OUTPUT = 65536
TOKEN = re.compile(r"[a-z0-9][a-z0-9+_.@/-]{0,127}\Z")
PREFERENCES = {
    "iconAppearance": ("NSGlobalDomain", "AppleIconAppearanceTheme"),
    "automaticAppearance": ("NSGlobalDomain", "AppleInterfaceStyleSwitchesAutomatically"),
    "showFileExtensions": ("NSGlobalDomain", "AppleShowAllExtensions"),
    "initialKeyRepeat": ("NSGlobalDomain", "InitialKeyRepeat"),
    "keyRepeat": ("NSGlobalDomain", "KeyRepeat"),
    "trackpadScaling": ("NSGlobalDomain", "com.apple.trackpad.scaling"),
    "widgetAppearance": ("com.apple.widgets", "widgetAppearance"),
    "dockAutohide": ("com.apple.dock", "autohide"),
    "minimizeIntoApplicationIcon": ("com.apple.dock", "minimize-to-application"),
    "reorderSpacesByRecentUse": ("com.apple.dock", "mru-spaces"),
    "dockRecents": ("com.apple.dock", "show-recents"),
    "bottomRightHotCornerRaw": ("com.apple.dock", "wvous-br-corner"),
    "finderPathBar": ("com.apple.finder", "ShowPathbar"),
    "finderStatusBar": ("com.apple.finder", "ShowStatusBar"),
    "tapToClick": ("com.apple.AppleMultitouchTrackpad", "Clicking"),
    "trackpadRightClick": ("com.apple.AppleMultitouchTrackpad", "TrackpadRightClick"),
    "threeFingerDrag": ("com.apple.AppleMultitouchTrackpad", "TrackpadThreeFingerDrag"),
    "stageManager": ("com.apple.WindowManager", "GloballyEnabled"),
    "clickWallpaperToShowDesktop": ("com.apple.WindowManager", "EnableStandardClickToShowDesktop"),
    "nativeWindowTiling": ("com.apple.WindowManager", "EnableTilingByEdgeDrag"),
    "tiledWindowMargins": ("com.apple.WindowManager", "EnableTiledWindowMargins"),
    "screenshotLocationClass": ("com.apple.screencapture", "location"),
}
POWER_KEYS = {"batteryLowPowerMode", "acLowPowerMode"}


def managed_preferences(manifest):
    policy = manifest["preferenceOwnership"]
    keys = policy["managedKeys"]
    if (policy.get("mode") != "owner-editable-preserved" or
            policy.get("historicalPrestateReplayAllowed") is not False or
            type(keys) is not list or len(keys) > 32 or
            any(type(key) is not str or key not in set(PREFERENCES) | POWER_KEYS for key in keys) or
            len(set(keys)) != len(keys)):
        raise ValueError("preference_ownership")
    return keys


def preference_plan(manifest):
    """Exact opt-in write scope. This plan does not execute settings commands."""
    keys = managed_preferences(manifest)
    desired = manifest["desiredState"]
    return {"defaults": sorted(key for key in keys if key in PREFERENCES),
            "power": {key: desired[key] for key in sorted(POWER_KEYS.intersection(keys))},
            "historicalReplay": False}


def declaration(manifest):
    policy = manifest["ownershipObservation"]
    if policy.get("automaticAdoption") is not False:
        raise ValueError("automatic_adoption_forbidden")
    result = {}
    for kind in ("formula", "cask"):
        values = policy["homebrewCollisions"][kind]
        if type(values) is not list or len(values) > 32:
            raise ValueError("collision_declaration")
        if any(type(v) is not str or not TOKEN.fullmatch(v) for v in values):
            raise ValueError("collision_declaration")
        if len(set(values)) != len(values):
            raise ValueError("collision_declaration")
        result[kind] = values
    return result


def collect_homebrew_conflicts(manifest, runner):
    """Compare exact installed package names, not global emptiness.

    Brew output is sampled boundedly, never returned or executed. An unavailable
    inventory is UNKNOWN only for this operation's declared collision set.
    """
    collisions = declaration(manifest)
    if manifest.get("profileActive") is False:
        collisions = {"formula": [], "cask": []}
    found = {"formula": [], "cask": []}
    observed = True
    for kind, relevant in collisions.items():
        if not relevant:
            continue
        try:
            result = runner(["/opt/homebrew/bin/brew", "list", "--" + kind])
            output = result.stdout
            if isinstance(output, bytes):
                output = output.decode("utf-8", "strict")
            if result.returncode != 0 or type(output) is not str or len(output) > MAX_OUTPUT:
                observed = False
                continue
            names = output.splitlines()
            if len(names) > 4096 or any(not TOKEN.fullmatch(name) for name in names):
                observed = False
                continue
            found[kind] = sorted(set(names).intersection(relevant))
        except (OSError, ValueError, UnicodeError, TypeError, AttributeError, subprocess.SubprocessError):
            observed = False
    conflict = any(found.values())
    return {"status": "conflict" if conflict else ("clear" if observed else "unknown"),
            "formulaConflicts": found["formula"], "caskConflicts": found["cask"],
            "observed": observed, "automaticAdoption": False,
            "coverage": "declared-homebrew-package-collisions-only"}


def classify_observation(*, managed, present, identity_matches=None,
                         competing_owner=False, authority_bearing=False,
                         signature_valid=None, observed=True):
    """Pure targeted metadata adjudication, no owner/app data or auto repair.

    External presence (including unsigned ordinary apps) is an observation.
    It cannot become execution, credential or adoption authority. A managed
    replacement/missing target or a competing primary owner is concrete conflict;
    unsigned authority-bearing use remains blocked, not silently approved.
    """
    if any(type(v) is not bool for v in
           (managed, present, competing_owner, authority_bearing, observed)):
        raise ValueError("observation_type")
    if any(v is not None and type(v) is not bool for v in (identity_matches, signature_valid)):
        raise ValueError("observation_type")
    reason = "external_presence" if present else "external_absence"
    state = "external-observed"
    if not observed or (managed and present and identity_matches is None):
        state, reason = "unknown", "required_observation_unavailable"
    elif competing_owner:
        state, reason = "conflict", "competing_primary_owner"
    elif managed and not present:
        state, reason = "conflict", "managed_target_missing"
    elif managed and identity_matches is False:
        state, reason = "conflict", "managed_identity_changed"
    elif authority_bearing and present and signature_valid is not True:
        state, reason = ("unknown", "signature_unavailable") if signature_valid is None else ("conflict", "unsigned_authority_use")
    elif managed:
        state, reason = "managed", "declared_identity_matches"
    return {"state": state, "reason": reason, "automaticAdoption": False,
            "automaticRepair": False, "executionAuthorized": False,
            "completeInventory": False}


def targeted_application_collision(manifest, app, *, lstat=os.lstat, samefile=os.path.samefile):
    """Inspect only a declared basename in the canonical external app root.

    A same-object alias is not another installer. Missing basename is absent,
    not a complete inventory claim. Permission/type/parent errors are UNKNOWN.
    Unknown raw paths/errors never escape this function.
    """
    external = Path(manifest["ownershipObservation"]["targetedExternalApplicationRoot"])
    managed = Path(manifest["target"]["applicationRoot"]) / app["bundleName"]
    candidate = external / app["bundleName"]
    try:
        if not stat.S_ISDIR(lstat(external).st_mode):
            return "unknown"
        lstat(candidate)
        try:
            if samefile(candidate, managed):
                return "clear"
        except FileNotFoundError:
            pass
        return "conflict"
    except FileNotFoundError:
        # Only a basename absence under an observed directory is known absence.
        try:
            return "clear" if stat.S_ISDIR(lstat(external).st_mode) else "unknown"
        except OSError:
            return "unknown"
    except OSError:
        return "unknown"


CATALOG_FILES = (
    "productivity-baseline.json", "phase3-capabilities.json", "codex-contract.json",
    "rustdesk-mac-controller.json", "tailscale-windows-host-m1.json",
    "windows-app-rdp-client.json", "amnezia-desktop.json", "gametomac.json",
)
METADATA_SCOPES = ("applications", "nix-applications", "user-applications", "home-manager-applications",
    "homebrew-cellar", "homebrew-caskroom", "homebrew-bin", "usr-local-bin", "local-bin", "aid-bin",
    "system-launch-agents", "system-launch-daemons", "user-launch-agents")
EXTERNAL_METADATA_SCOPES = {"applications", "user-applications", "homebrew-cellar", "homebrew-caskroom"}


def _metadata_key(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _summary(**counts):
    value = {key: counts.get(key, 0) for key in ("managed", "externalObserved", "conflict", "unknown")}
    value.update(requiredReview=bool(value["managed"] + value["conflict"] + value["unknown"]),
                 actorAttributed=False, completeInventory=False)
    return value


def _declared_path(path):
    if type(path) is not str or len(path) > 1024 or any(char in path for char in ("\x00", "\n", "\r")):
        raise ValueError("catalog_path")
    if not (path.startswith("/") or path.startswith("$HOME/")):
        raise ValueError("catalog_path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("catalog_path")


def declared_metadata_catalog(root):
    """Bind bounded *source* declarations, never discover installed inventory.

    Fixed app contracts are current authority-bearing/adopted targets. Disabled
    payloads do not regain management just because historical paths remain.
    Source load ambiguity is UNKNOWN to the consumer, not a new desired catalog.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("catalog_duplicate_key")
            result[key] = value
        return result
    values = {}
    for name in CATALOG_FILES:
        raw = (Path(root) / "manifests" / name).read_bytes()
        if len(raw) > 131072:
            raise ValueError("catalog_bound")
        value = json.loads(raw, object_pairs_hook=unique)
        if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1:
            raise ValueError("catalog_schema")
        for flag in ("profileActive", "enabled"):
            if flag in value and type(value[flag]) is not bool:
                raise ValueError("catalog_enabled_type")
        values[name] = value
    catalog = {key: set() for key in METADATA_SCOPES}
    def app_path(path, *, required=False):
        _declared_path(path)
        if not path.startswith("/Applications/"):
            if required:
                raise ValueError("catalog_required_application_path")
            return
        suffix = path[len("/Applications/"):]
        parts = suffix.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("catalog_path")
        if parts[0] == "Nix Apps" and len(parts) > 1:
            catalog["nix-applications"].add(_metadata_key(parts[1]))
            catalog["applications"].add(_metadata_key("Nix Apps"))
        elif parts[0].endswith(".app"):
            catalog["applications"].add(_metadata_key(parts[0]))
        elif required:
            raise ValueError("catalog_required_application_path")
    productivity = values["productivity-baseline.json"]
    if type(productivity.get("profileActive")) is not bool or productivity["target"]["applicationRoot"] != "/Applications/Nix Apps":
        raise ValueError("catalog_productivity_target")
    if productivity.get("profileActive") is True:
        for app in productivity["applications"]:
            if type(app["bundleName"]) is not str or "/" in app["bundleName"] or not app["bundleName"].endswith(".app"):
                raise ValueError("catalog_productivity_bundle")
            app_path(productivity["target"]["applicationRoot"] + "/" + app["bundleName"], required=True)
            # Canonical duplicate basename is relevant, but its mere metadata
            # addition is not enough to diagnose a distinct installer/alias.
            app_path("/Applications/" + app["bundleName"], required=True)
        collisions = declaration(productivity)
        catalog["homebrew-cellar"].update(_metadata_key(name) for name in collisions["formula"])
        catalog["homebrew-caskroom"].update(_metadata_key(name) for name in collisions["cask"])
    retired = set()
    for name in ("rustdesk-mac-controller.json", "tailscale-windows-host-m1.json",
                 "windows-app-rdp-client.json", "amnezia-desktop.json", "gametomac.json"):
        value = values[name]
        path = value["application"]["path"]
        flag = "enabled" if name == "gametomac.json" else "profileActive"
        if type(value.get(flag)) is not bool or type(path) is not str or not re.fullmatch(r"/Applications/[^/]+[.]app", path):
            raise ValueError("catalog_application_target")
        if value[flag] is False:
            retired.add(path.split("/")[2])
        else:
            app_path(path, required=True)
    app_path(values["codex-contract.json"]["cli"]["canonicalPath"], required=True)
    for identity in values["phase3-capabilities.json"]["logical_identities"]:
        path = identity["path"]
        _declared_path(path)
        if path.startswith("/Applications/") and path.split("/")[2] not in retired:
            # These declared browser/VPN/agent identities consume privileges;
            # arbitrary new external apps never inherit this classification.
            app_path(path)
    return catalog


def classify_metadata_change(previous, current, *, catalog):
    """Count-only change classification; no invented actor, version or trust.

    App/package metadata outside declared targets is external-observed, not a
    request for ownership admission. Command/service and managed-namespace
    differences lacking targeted identity evidence remain UNKNOWN. Root-only
    changes/coverage loss are UNKNOWN; root metadata accompanying entry changes
    is counted with their classifications, not attributed to an installer.
    """
    if previous is None:
        return _summary()
    counts = _summary()
    for scope in METADATA_SCOPES:
        before, after = previous["scopes"][scope], current["scopes"][scope]
        a, b = before["entries"], after["entries"]
        affected = (a.keys() ^ b.keys()) | {key for key in a.keys() & b.keys() if a[key] != b[key]}
        if before["present"] is not after["present"]:
            counts["unknown"] += 1
        elif before["root"] != after["root"] and not affected:
            counts["unknown"] += 1
        for key in affected:
            if key in catalog[scope]:
                state = "conflict" if key not in b and scope in {"nix-applications", "home-manager-applications"} else "managed"
            elif scope in EXTERNAL_METADATA_SCOPES:
                # Wire the same observation classifier used by payload doctors.
                evidence = classify_observation(managed=False, present=key in b)
                state = "externalObserved" if evidence["state"] == "external-observed" else "unknown"
            else:
                state = "unknown"
            counts[state] += 1
    return _summary(**counts)


def metadata_change_classifier(root):
    """Bind catalog once before capture. Bad/missing source stays UNKNOWN."""
    try:
        catalog = declared_metadata_catalog(root)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return lambda previous, current: _summary(unknown=1)
    return lambda previous, current: classify_metadata_change(previous, current, catalog=catalog)
