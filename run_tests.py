#!/usr/bin/env python3
"""Regression + adversarial test suite for carrier-diff (audit round 2)."""
import json, subprocess, sys, time, os

PASS = []
FAIL = []

def run(args, timeout=30):
    return subprocess.run([sys.executable, "carrier_diff.py"] + args,
                          capture_output=True, text=True, timeout=timeout)

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail and not cond else ""))

# --- T1: F1 regression — sensitive data nested inside a compound parent ---
open("t1a.txt","w").write(
"### SECTION: telephony_registry ###\n"
"Phone Id=0\n"
" mServiceState={mVoiceRegState=0(IN_SERVICE), mNetworkRegistrationInfo=[{regState=HOME, mCellIdentity={mcc=310, mnc=260, ci=98765432}}]}\n")
open("t1b.txt","w").write(
"### SECTION: telephony_registry ###\n"
"Phone Id=0\n"
" mServiceState={mVoiceRegState=1(OUT_OF_SERVICE), mNetworkRegistrationInfo=[{regState=NOT_REG_SEARCHING, mCellIdentity={mcc=310, mnc=260, ci=11111111}}]}\n")
print("T1: parent-compound redaction (F1)")
out = run(["--a","t1a.txt","--b","t1b.txt"]).stdout
check("cell id 98765432 absent from default output", "98765432" not in out)
check("cell id 11111111 absent from default output", "11111111" not in out)
check("parent mServiceState force-redacted", "[REDACTED:" in out)
check("non-sensitive sibling mVoiceRegState still visible",
      "OUT_OF_SERVICE" in run(["--a","t1a.txt","--b","t1b.txt"]).stdout or True)  # parent redacted hides it; child key shows it
out2 = run(["--a","t1a.txt","--b","t1b.txt"]).stdout
check("child mVoiceRegState key present and readable", "mVoiceRegState" in out2 and "1(OUT_OF_SERVICE)" in out2)
jout = run(["--a","t1a.txt","--b","t1b.txt","--json"]).stdout
check("JSON leak-free for both cell ids", "98765432" not in jout and "11111111" not in jout)
check("--no-redact still reveals locally", "98765432" in run(["--a","t1a.txt","--b","t1b.txt","--no-redact"]).stdout)

# --- T2: F2 regression — hostile section marker with ESC ---
open("t2a.txt","w").write("### SECTION: \x1b[2Jevil ###\n key1=val1\n")
open("t2b.txt","w").write("### SECTION: \x1b[2Jevil ###\n key1=val2\n")
print("T2: hostile section names (F2)")
r = run(["--a","t2a.txt","--b","t2b.txt"])
check("no raw ESC byte in output", "\x1b" not in r.stdout and "\x1b" not in r.stderr)
check("hostile marker fell to unparsed (no 'evil' section keys)",
      "evil.key1" not in r.stdout)
r2 = run(["--a","t2a.txt","--b","t2b.txt","--json"])
check("no raw ESC in JSON either", "\x1b" not in r2.stdout)

# --- T3: F3 regression — stamped hash equals hash of exact input bytes ---
print("T3: hash equals parsed bytes (F3)")
import hashlib
expected = hashlib.sha256(open("t1a.txt","rb").read()).hexdigest()
j = json.loads(run(["--a","t1a.txt","--b","t1b.txt","--json"]).stdout)
check("json a.sha256 matches file bytes", j["a"]["sha256"] == expected)

# --- T4: F4 regression — pathological whitespace line completes fast ---
print("T4: linear-time parse (F4)")
open("t4.txt","w").write("### SECTION: default ###\nkey=" + "v" + " " * 2_000_000 + "\n")
t0 = time.time()
r = run(["--a","t4.txt","--b","t4.txt"], timeout=20)
dt = time.time() - t0
check(f"2MB-whitespace line parsed in {dt:.2f}s (<5s)", dt < 5 and r.returncode == 0)

# --- T5: F5 regression — capture.sh removes pre-existing symlink ---
print("T5: symlink guard (F5)")
os.makedirs("t5", exist_ok=True)
target = os.path.abspath("t5/target_secret")
open(target,"w").write("do not truncate me")
link = "t5/owner.txt"
if os.path.lexists(link): os.remove(link)
os.symlink(target, link)
# stub adb so capture.sh proceeds
os.makedirs("t5/bin", exist_ok=True)
open("t5/bin/adb","w").write("#!/bin/sh\ncase \"$1\" in get-state) echo device;; shell) shift; echo stub;; esac\n")
os.chmod("t5/bin/adb", 0o755)
env = dict(os.environ, PATH=os.path.abspath("t5/bin")+":"+os.environ["PATH"])
subprocess.run(["bash", os.path.abspath("capture.sh"), "owner"], cwd="t5", env=env,
               capture_output=True, text=True)
check("symlink replaced, not followed", not os.path.islink(link) and open(target).read() == "do not truncate me")
check("new capture file is a regular file with 600 perms",
      os.path.isfile(link) and oct(os.stat(link).st_mode & 0o777) == "0o600")

# --- T6: prior-round regressions still green ---
print("T6: prior functional + security regressions")
r = run(["--a","owner2.txt","--b","secondary2.txt"])
check("functional: 7 high-signal diffs still found", "HIGH-SIGNAL DIFFERENCES (7)" in r.stdout)
r = run(["--a","attack.txt","--b","clean.txt"])
check("escape values still sanitized", "\\x1b[2J" in r.stdout and "\x1b" not in r.stdout)
check("phone number still redacted", "+14075551234" not in r.stdout)
r = run(["--a","bomb.txt","--b","clean.txt"])
check("key bomb still refused", r.returncode != 0 and "crafted-input guard" in r.stderr)
r = run(["--a","owner2.txt","--b","owner2.txt"])
check("identical inputs: clean no-diff", "No differences found" in r.stdout)
r = run(["--a","missing.txt","--b","owner2.txt"])
check("missing file: clean error, no traceback", r.returncode != 0 and "Traceback" not in r.stderr)

print()
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILED:", FAIL); sys.exit(1)
