#!/usr/bin/env python3
"""
carrier-diff — Android telephony state differ for multi-user debugging.

Compares two telephony capture files (e.g. Owner profile vs secondary user)
and reports differences in carrier configuration, service state, and
registration state. Built to support triage of per-profile telephony
failures (e.g. secondary user "no mobile network available" while Owner
works fine).

Input files are produced by capture.sh (bundled) or manually via:
    adb shell dumpsys carrier_config      > owner_carrier.txt
    adb shell dumpsys telephony.registry  > owner_registry.txt

Usage:
    carrier_diff.py --a owner.txt --b secondary.txt
    carrier_diff.py --a owner.txt --b secondary.txt --json
    carrier_diff.py --a owner.txt --b secondary.txt --section carrier_config

No dependencies beyond the Python standard library.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Registration / service-state fields: the high-signal set for
# "no mobile network" class bugs.
SIGNAL_KEYS = (
    "mServiceState",
    "mVoiceRegState",
    "mDataRegState",
    "mNetworkRegistrationInfo",
    "mVoiceRoamingType",
    "mDataRoamingType",
    "mCellIdentity",
    "mOperatorAlphaLong",
    "mOperatorNumeric",
    "mIsEmergencyOnly",
    "mCallState",
    "mDataConnectionState",
    "mDataEnabled",
    "mSimState",
    "mPhoneCapability",
    "mActiveSubId",
    "mDefaultSubId",
    "mDefaultPhoneId",
)

# Section/service names are attacker-influenced: restrict to a safe charset
# (fail closed — hostile markers fall through to unparsed).
SECTION_MARKER_RE = re.compile(r"^### SECTION: ([A-Za-z0-9_.\-]+) ###\s*$")
DUMPSYS_HEADER_RE = re.compile(r"^DUMP OF SERVICE ([A-Za-z0-9_.\-]+):?\s*$")
PHONE_ID_RE = re.compile(r"^\s*Phone\s*Id\s*[=:]?\s*(\d+)\s*$", re.IGNORECASE)
# Greedy capture + rstrip in code: linear-time, no lazy backtracking (ReDoS guard).
KV_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:][ \t]*(.*)$")
# Dumpsys local-log history entries: an ISO-ish timestamp followed by
# " - message". These are event history, not state — routing them into the
# key space floods the diff with noise (observed on live Pixel captures).
LOG_LINE_RE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\s+-\s")

# Map dumpsys service names to canonical section names.
SERVICE_SECTION = {
    "carrier_config": "carrier_config",
    "telephony.registry": "telephony_registry",
    "isub": "subscription",
    "user": "user_restrictions",
}

MAX_EXPLODE_DEPTH = 5

# Resource caps: a capture file is untrusted input. These bound memory and
# CPU against crafted inputs (oversized files, compound-explosion bombs).
MAX_FILE_BYTES = 64 * 1024 * 1024   # 64 MiB
MAX_KEYS = 250_000

# Keys whose values are personal or trackable identifiers. Redacted by
# default in all output; each value is replaced with a short hash so diffs
# still show WHETHER values differ without exposing WHAT they are.
SENSITIVE_KEY_PARTS = (
    "mCallIncomingNumber",
    "mCallForwardingNumber",
    "line1Number",
    "IncomingNumber",
    "OutgoingNumber",
    "iccid",
    "Iccid",
    "imsi",
    "Imsi",
    "imei",
    "Imei",
    "subscriberId",
    "mCellIdentity",
    "CellIdentity",
    "meid",
    "Meid",
)

CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class KeyCapExceeded(Exception):
    def __init__(self, path):
        super().__init__(path)
        self.path = path


@dataclass
class Capture:
    """Parsed representation of one capture file."""
    path: str
    kv: dict = field(default_factory=dict)          # flat key -> value
    dup_counts: dict = field(default_factory=dict)  # base key -> occurrences
    unparsed: list = field(default_factory=list)    # lines we couldn't parse
    sensitive: set = field(default_factory=set)     # keys force-redacted
                                                    # (sensitive descendants)
    sha256: str = ""                                # hash of exact parsed bytes


def split_pairs(body: str) -> list:
    """Split 'k=v, k2=v2, ...' on commas at bracket depth 0.

    Handles nested {}, [], () so compound values like
    mServiceState={a=1, b={c=2, d=3}} split correctly at the top level.
    """
    parts, depth, buf = [], 0, []
    for ch in body:
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def compound_body(value: str) -> tuple[str, str] | None:
    """Return (kind, inner body) if value is a compound we can explode.

    kind 'pairs': body is 'k=v, k2=v2, ...'
    kind 'list':  body is comma-separated elements (each may be compound)
    """
    m = re.match(r"^Bundle\[\{(.*)\}\]$", value)
    if m:
        return ("pairs", m.group(1))
    if value.startswith("{") and value.endswith("}"):
        return ("pairs", value[1:-1])
    if value.startswith("[") and value.endswith("]"):
        return ("list", value[1:-1])
    return None


def store(cap: Capture, key: str, value: str, depth: int = 0) -> bool:
    """Store a key, suffixing duplicates, and explode compound values.

    Returns True if this key or any descendant is sensitive. Ancestors of
    sensitive descendants are force-redacted (their raw compound value
    embeds the sensitive data — redacting only the child would leak it
    through the parent)."""
    if len(cap.kv) >= MAX_KEYS:
        raise KeyCapExceeded(cap.path)
    base = key
    n = cap.dup_counts.get(base, 0)
    cap.dup_counts[base] = n + 1
    if n:
        key = f"{base}#{n + 1}"
    cap.kv[key] = value

    child_sensitive = False
    if depth < MAX_EXPLODE_DEPTH:
        compound = compound_body(value)
        if compound is not None:
            kind, body = compound
            if kind == "pairs":
                for pair in split_pairs(body):
                    m = KV_RE.match(pair)
                    if m:
                        child_sensitive |= store(
                            cap, f"{key}.{m.group(1)}",
                            m.group(2).rstrip(), depth + 1)
            else:  # list: index-keyed elements, each may itself be compound
                for i, elem in enumerate(split_pairs(body)):
                    child_sensitive |= store(
                        cap, f"{key}.{i}", elem, depth + 1)
    self_sensitive = is_sensitive_key(key)
    # Value-level taint scan: the security property must NOT depend on the
    # exploder fully understanding the value's shape. If a sensitive token
    # appears anywhere in the raw value (deeper than the explosion depth
    # cap, or inside a shape we can't parse), force-redact this key.
    value_sensitive = any(part in value for part in SENSITIVE_KEY_PARTS)
    if (child_sensitive or value_sensitive) and not self_sensitive:
        cap.sensitive.add(key)
    return self_sensitive or child_sensitive or value_sensitive


def parse_capture(path: str) -> Capture:
    cap = Capture(path=path)
    section = "default"
    phone_ctx = None
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_FILE_BYTES + 1)
    except OSError as e:
        sys.exit(f"error: cannot read {path}: {e}")
    if len(data) > MAX_FILE_BYTES:
        sys.exit(f"error: {path} exceeds {MAX_FILE_BYTES} byte cap"
                 " (crafted-input guard)")
    # Hash and parse the SAME bytes from a single read: the stamped hash
    # provably describes the analyzed content (no check/use race).
    cap.sha256 = hashlib.sha256(data).hexdigest()
    lines = data.decode("utf-8", errors="replace").splitlines()

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue

        m = SECTION_MARKER_RE.match(line)
        if m:
            section = m.group(1)
            phone_ctx = None
            continue

        m = DUMPSYS_HEADER_RE.match(line)
        if m:
            section = SERVICE_SECTION.get(m.group(1), m.group(1))
            phone_ctx = None
            continue

        m = PHONE_ID_RE.match(line)
        if m:
            phone_ctx = f"phone{m.group(1)}"
            continue

        if LOG_LINE_RE.match(line):
            cap.unparsed.append(line)
            continue

        m = KV_RE.match(line)
        if m:
            prefix = f"{section}.{phone_ctx}." if phone_ctx else f"{section}."
            try:
                store(cap, prefix + m.group(1), m.group(2).rstrip())
            except KeyCapExceeded:
                sys.exit(f"error: {path} produced more than {MAX_KEYS}"
                         " parsed keys, refusing to continue"
                         " (crafted-input guard)")
        else:
            cap.unparsed.append(line)
    return cap


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    changed: list = field(default_factory=list)   # (key, a_val, b_val)
    only_a: list = field(default_factory=list)    # (key, a_val)
    only_b: list = field(default_factory=list)    # (key, b_val)

    def is_empty(self) -> bool:
        return not (self.changed or self.only_a or self.only_b)


def diff_captures(a: Capture, b: Capture, section: str | None) -> DiffResult:
    result = DiffResult()
    keys_a = {k: v for k, v in a.kv.items()
              if section is None or k.startswith(section + ".")}
    keys_b = {k: v for k, v in b.kv.items()
              if section is None or k.startswith(section + ".")}

    for key in sorted(set(keys_a) | set(keys_b)):
        va, vb = keys_a.get(key), keys_b.get(key)
        if va is not None and vb is not None:
            if va != vb:
                result.changed.append((key, va, vb))
        elif va is not None:
            result.only_a.append((key, va))
        else:
            result.only_b.append((key, vb))
    return result


def is_signal_key(key: str) -> bool:
    short = key.rsplit(".", 1)[-1].split("#")[0]
    return any(sk in short for sk in SIGNAL_KEYS)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def sanitize(s: str) -> str:
    """Neutralize terminal control characters in untrusted values (escape
    injection defense). Renders them as visible \\xNN escapes."""
    return CTRL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", s)


def is_sensitive_key(key: str) -> bool:
    return any(part in key for part in SENSITIVE_KEY_PARTS)


def redact(key: str, value: str, enabled: bool, forced: set) -> str:
    """Replace sensitive values with a stable short hash. Empty stays
    visible as empty (its absence is diagnostic, not identifying)."""
    if not enabled or value == "":
        return value
    if not is_sensitive_key(key) and key not in forced:
        return value
    h = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return f"[REDACTED:{h}]"


def fmt(s: str, width: int = 60) -> str:
    if s == "":
        return "(empty)"
    s = sanitize(s)
    return s if len(s) <= width else s[: width - 3] + "..."


def print_human(diff: DiffResult, a: Capture, b: Capture,
                redact_on: bool) -> None:
    forced = a.sensitive | b.sensitive
    print("carrier-diff")
    print(f"  A: {sanitize(a.path)}  ({len(a.kv)} keys parsed)"
          f"  sha256:{a.sha256[:16]}")
    print(f"  B: {sanitize(b.path)}  ({len(b.kv)} keys parsed)"
          f"  sha256:{b.sha256[:16]}")
    print(f"  redaction: {'ON (default; --no-redact to disable)' if redact_on else 'OFF'}")
    print()

    if diff.is_empty():
        print("No differences found in parsed keys.")
        print("If a real behavioral difference exists, the relevant state may"
              " not be in these dumps — capture telephony.registry and"
              " carrier_config for BOTH profiles while each is active.")
        return

    high = [c for c in diff.changed if is_signal_key(c[0])]
    low = [c for c in diff.changed if not is_signal_key(c[0])]

    if high:
        print(f"HIGH-SIGNAL DIFFERENCES ({len(high)}) — registration/service state:")
        for key, va, vb in high:
            print(f"  {sanitize(key)}")
            print(f"    A: {fmt(redact(key, va, redact_on, forced))}")
            print(f"    B: {fmt(redact(key, vb, redact_on, forced))}")
        print()

    if low:
        print(f"OTHER CHANGED KEYS ({len(low)}):")
        for key, va, vb in low:
            print(f"  {sanitize(key)}:"
                  f" {fmt(redact(key, va, redact_on, forced), 40)}"
                  f"  ->  {fmt(redact(key, vb, redact_on, forced), 40)}")
        print()

    if diff.only_a:
        print(f"ONLY IN A ({len(diff.only_a)}):")
        for key, va in diff.only_a:
            marker = "  [signal]" if is_signal_key(key) else ""
            print(f"  {sanitize(key)} ="
                  f" {fmt(redact(key, va, redact_on, forced), 50)}{marker}")
        print()

    if diff.only_b:
        print(f"ONLY IN B ({len(diff.only_b)}):")
        for key, vb in diff.only_b:
            marker = "  [signal]" if is_signal_key(key) else ""
            print(f"  {sanitize(key)} ="
                  f" {fmt(redact(key, vb, redact_on, forced), 50)}{marker}")
        print()


def to_json(diff: DiffResult, a: Capture, b: Capture,
            redact_on: bool) -> str:
    forced = a.sensitive | b.sensitive
    return json.dumps(
        {
            "a": {"path": sanitize(a.path), "keys_parsed": len(a.kv),
                  "sha256": a.sha256},
            "b": {"path": sanitize(b.path), "keys_parsed": len(b.kv),
                  "sha256": b.sha256},
            "redaction": redact_on,
            "changed": [
                {"key": sanitize(k),
                 "a": sanitize(redact(k, va, redact_on, forced)),
                 "b": sanitize(redact(k, vb, redact_on, forced)),
                 "signal": is_signal_key(k)}
                for k, va, vb in diff.changed
            ],
            "only_a": [
                {"key": sanitize(k),
                 "value": sanitize(redact(k, v, redact_on, forced)),
                 "signal": is_signal_key(k)}
                for k, v in diff.only_a
            ],
            "only_b": [
                {"key": sanitize(k),
                 "value": sanitize(redact(k, v, redact_on, forced)),
                 "signal": is_signal_key(k)}
                for k, v in diff.only_b
            ],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        prog="carrier-diff",
        description="Diff two Android telephony state captures"
                    " (e.g. Owner vs secondary user).",
    )
    p.add_argument("--a", required=True, help="capture file A (e.g. owner)")
    p.add_argument("--b", required=True, help="capture file B (e.g. secondary)")
    p.add_argument("--section", default=None,
                   help="restrict diff to one section"
                        " (carrier_config, telephony_registry, subscription,"
                        " user_restrictions)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--show-unparsed", action="store_true",
                   help="print line counts the parser could not classify")
    p.add_argument("--no-redact", action="store_true",
                   help="disable default redaction of sensitive identifiers"
                        " (numbers, ICCID/IMSI/IMEI, cell identity)")
    args = p.parse_args()
    redact_on = not args.no_redact

    cap_a = parse_capture(args.a)
    cap_b = parse_capture(args.b)
    diff = diff_captures(cap_a, cap_b, args.section)

    if args.json:
        print(to_json(diff, cap_a, cap_b, redact_on))
    else:
        print_human(diff, cap_a, cap_b, redact_on)
        if args.show_unparsed:
            print(f"unparsed lines: A={len(cap_a.unparsed)}"
                  f" B={len(cap_b.unparsed)}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
