"""Pure private rollback compositions, never a config writer or live admission.

Only two proved root-scalar value spans may be replaced. Missing historical
keys remove their assignment tokens, retaining current comments/whitespace.
All source bytes outside those edits are copied unchanged; return is exactly
the caller's current bytes. Caller owns receipt binding, descriptor identity,
integration admission and any separately authorized future dispatch.
"""

import json
import math
import re

from vendor.tomli import TOMLDecodeError, loads


MAX_CONFIG_BYTES = 1024 * 1024
MAX_CANDIDATES = 16
MANAGED = {"approval_policy": "never", "sandbox_mode": "danger-full-access"}
ALLOWED = {
    "approval_policy": frozenset(("never", "on-request", "untrusted")),
    "sandbox_mode": frozenset(("danger-full-access", "workspace-write", "read-only")),
}
# This is a candidate locator, NOT a TOML parser or a scope classifier. Every
# candidate must pass the robust parser's independent root-change proof below.
ASSIGNMENT = re.compile(
    rb'^[ \t]*(?P<key>approval_policy|sandbox_mode)[ \t]*=[ \t]*'
    rb'(?P<value>"(?:[^"\\\r\n]|\\[^\r\n])*"|\x27[^\x27\r\n]*\x27)'
    rb'[ \t]*(?:\#[^\r\n]*)?(?:\r?\n|\Z)', re.MULTILINE,
)
SENTINEL = "__phase5_private_root_span_probe__"


class CompositionError(ValueError):
    """Fixed public reason only; never include private parser diagnostics."""


def _parse(raw):
    if type(raw) is not bytes or len(raw) > MAX_CONFIG_BYTES:
        raise CompositionError("composition_bytes_invalid") from None
    try:
        return loads(raw.decode("utf-8", "strict"))
    except (TOMLDecodeError, UnicodeError, ValueError, RecursionError, OverflowError):
        raise CompositionError("composition_toml_invalid") from None


def _same(left, right):
    # Only parser-created builtin/datetime values reach this function.
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    if type(left) is float and math.isnan(left) and math.isnan(right):
        return math.copysign(1, left) == math.copysign(1, right)
    return left == right


def _required(document):
    return all(type(document.get(key)) is str and document[key] == value
               for key, value in MANAGED.items())


def _span(raw, document, key, matches):
    proved = []
    expected = dict(document)
    expected[key] = SENTINEL
    for match in matches:
        if match.group("key").decode("ascii") != key:
            continue
        start, end = match.span("value")
        probe = raw[:start] + json.dumps(SENTINEL).encode("ascii") + raw[end:]
        try:
            parsed = _parse(probe)
        except CompositionError:
            continue
        if _same(parsed, expected):
            proved.append((match.start("key"), start, end))
    if len(proved) != 1:
        raise CompositionError("composition_scalar_span_unproved") from None
    return proved[0]


def compose(historical_before, historical_after, current):
    """Return PRIVATE {current, rollback, return} bytes; no execution authority.

Historical before may omit either managed scalar, or contain its known simple
string enum. Historical after and current must contain the required values.
Unsupported quoted-key/multiline root-scalar formatting fails closed. No
historical comments, projects, integrations or other bytes are copied back.
"""
    before = _parse(historical_before)
    after = _parse(historical_after)
    observed = _parse(current)
    if not _required(after) or not _required(observed):
        raise CompositionError("composition_managed_state_invalid") from None
    for key in MANAGED:
        if key in before and (type(before[key]) is not str or before[key] not in ALLOWED[key]):
            raise CompositionError("composition_historical_scalar_invalid") from None
    expected_after = dict(before)
    expected_after.update(MANAGED)
    try:
        if not _same(after, expected_after):
            raise CompositionError("composition_historical_pair_invalid") from None
        matches = []
        for match in ASSIGNMENT.finditer(current):
            matches.append(match)
            if len(matches) > MAX_CANDIDATES:
                raise CompositionError("composition_candidate_limit") from None
        edits = []
        expected_rollback = dict(observed)
        for key in MANAGED:
            token_start, value_start, value_end = _span(current, observed, key, matches)
            if key in before:
                expected_rollback[key] = before[key]
                # Keep the original spelling/bytes when its semantic value is
                # already the rollback target; this can legitimately be a no-op.
                if before[key] != observed[key]:
                    edits.append((value_start, value_end, json.dumps(before[key]).encode("ascii")))
            else:
                del expected_rollback[key]
                edits.append((token_start, value_end, b""))
        rollback = current
        for start, end, replacement in sorted(edits, reverse=True):
            rollback = rollback[:start] + replacement + rollback[end:]
        parsed_rollback = _parse(rollback)
        if not _same(parsed_rollback, expected_rollback):
            raise CompositionError("composition_preservation_unproved") from None
    except RecursionError:
        raise CompositionError("composition_structure_limit") from None
    return {"current": current, "rollback": rollback, "return": current}
