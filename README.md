# carrier-diff

Android telephony state differ for multi-user debugging. Captures carrier
configuration, service state, and registration state per user profile and
diffs them to surface why telephony behaves differently between profiles.

Built for triaging per-profile telephony failures, e.g. a secondary user
seeing "no mobile network available" while the Owner profile calls fine on
the same device and SIM.

## Why

Android provisions telephony state per user. When calls fail only in a
secondary profile, the question is always: what does the secondary profile
not have that Owner does? Answering it by eyeballing two multi-thousand-line
`dumpsys` outputs is error-prone. This tool structures the comparison and
ranks registration/service-state differences first.

## Usage

**1. Capture both profiles** (requires adb, USB debugging enabled in each
profile being captured):

```
./capture.sh owner
# switch to the affected user on the device
./capture.sh secondary
```

**2. Diff:**

```
python3 carrier_diff.py --a owner.txt --b secondary.txt
```

High-signal differences (service state, voice/data registration, SIM state,
subscription mapping) are reported first, followed by all other changed
keys, then keys present in only one capture.

**Options:**

```
--section carrier_config     restrict diff to one section
--json                       machine-readable output
--show-unparsed              report lines the parser could not classify
```

## Output sections

| Section | Source | What it shows |
|---|---|---|
| carrier_config | dumpsys carrier_config | per-carrier feature flags and provisioning |
| telephony_registry | dumpsys telephony.registry | live service/registration/call state |
| subscription | dumpsys isub | subId to user/profile mapping |
| user_restrictions | dumpsys user | per-user restrictions incl. calls/SMS toggles |

## Security model

This tool treats capture files as **untrusted input** and its own output as
**potentially public**. Concretely:

- **Redaction by default.** Values for sensitive identifier keys (call
  numbers, ICCID/IMSI/IMEI, subscriber IDs, cell identity) are replaced
  with `[REDACTED:<hash8>]` in all output. Sensitivity is tainted through
  compound values: a parent whose raw value embeds a sensitive field
  (e.g. ServiceState containing CellIdentity) is force-redacted too, and
  a value-level token scan enforces this even for shapes the exploder
  cannot parse. The hash preserves diff semantics: you can see the values
  differ without exposing them. Use `--no-redact` only for local
  analysis.
- **Terminal escape injection defense.** All control characters in values
  are rendered as visible `\xNN` escapes. A crafted capture cannot
  manipulate your terminal through the diff output.
- **Crafted-input guards.** Input files are capped at 64 MiB and parsing
  aborts past 250,000 keys, bounding memory and CPU against compound
  explosion bombs.
- **Capture hygiene.** capture.sh validates the label against
  `[A-Za-z0-9_-]{1,32}` (path traversal guard) and writes captures with
  owner-only permissions (`umask 077`), since they contain device and
  subscriber identifiers.
- **Evidence integrity.** Each capture is read once; the SHA-256 stamped
  on every output is computed from the exact bytes that were parsed (no
  check/use race), so a shared diff is verifiable against the captures it
  came from.
- No network access, no subprocess execution, no dynamic evaluation.
  Standard library only.

Redaction is driven by the known-sensitive token list. Review output
before posting publicly regardless.

A regression suite (`run_tests.py`, 20 checks) covers functional parsing,
escape injection, redaction and compound-taint propagation, resource-bomb
guards, hash integrity, path traversal, and symlink handling. An
end-to-end harness with a mock adb exercises capture.sh's full runtime
path.

## Notes

- `dumpsys` output format varies across Android versions and OEM layers.
  The parser is tolerant (raw key/value fallback) but validate against your
  device's output. Regression-tested against synthetic AOSP-format fixtures (nested ServiceState, Bundle-packed config, per-phone blocks, CRLF). Validated against live Pixel 10 Pro (GrapheneOS) captures, where it isolated a per-profile carrier-app provisioning failure on first run. Dumpsys local-log history lines are filtered as noise.
- Captures can contain identifiers (IMSI-adjacent values, ICCID, cell IDs,
  operator numerics). Review before sharing captures or diff output
  publicly. The diff output truncates values but does not redact them.
- No dependencies beyond the Python standard library. Runs on Python 3.8+
  (annotations deferred via __future__ import; validated on macOS system
  Python and 3.12).

## License

MIT
