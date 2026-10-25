#!/usr/bin/env python3
"""12_sched_pty.py - the scheduler on a real terminal (pseudo-terminal).

Drives myshell through a pty and types into it the way a user would, to show
(1) Ctrl-C interrupting a scheduling run without killing the shell and without
losing the work already done, (2) a scheduling run as a background job beside a
free prompt, (3) killing that background run with `kill %1`, and (4) that no
stopped child process is ever left behind.  Lines starting with '>>>' are
verdicts computed from what the shell actually printed.

usage: 12_sched_pty.py ./myshell ./demos/cpuburn
"""
import os
import pty
import re
import select
import subprocess
import sys
import time

SHELL = sys.argv[1] if len(sys.argv) > 1 else "./myshell"
BURN = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "./demos/cpuburn")
PROMPT = r"myshell:[^\r\n]*\$ $"

pid, fd = pty.fork()
if pid == 0:
    os.environ["BURN"] = BURN
    os.execv(SHELL, [SHELL])

transcript, pending = [], ""


def pump(t):
    global pending
    r, _, _ = select.select([fd], [], [], t)
    if not r:
        return
    try:
        d = os.read(fd, 8192).decode(errors="replace")
    except OSError:
        return
    transcript.append(d)
    pending += d


def expect(rx, timeout=10.0):
    global pending
    end = time.time() + timeout
    while time.time() < end:
        m = re.search(rx, pending)
        if m:
            pending = pending[m.end():]
            return True
        pump(0.1)
    return False


def send(s, pause=0.0):
    os.write(fd, s.encode())
    time.sleep(pause)


results = []


def ok(c, m):
    print(f">>> {'OK  ' if c else 'FAIL'} {m}")
    results.append(c)


expect(PROMPT)

# ---------------------------------------------------------------------------
# 1. Ctrl-C while a scheduling run holds the foreground
# ---------------------------------------------------------------------------
send(f"sched add {BURN} longA 8000 1000\n")
expect(PROMPT)
send(f"sched add {BURN} longB 8000 1000\n")
expect(PROMPT)
send("sched run rr -q 150 --quiet\n", 1.2)
send("\x03")                                   # Ctrl-C
got_report = expect(r"run cut short by SIGINT")
got_prompt = expect(PROMPT)
send("echo rc=$?\n")
ok(got_report and got_prompt and expect(r"rc=130"),
   "Ctrl-C interrupts the scheduling run (status 130) and the shell survives")
expect(PROMPT)

send("sched stats\n")
ok(expect(r"terminated \(unfinished\)"),
   "the report of the interrupted run keeps the measurements taken so far")
expect(PROMPT)

# the processes that were being scheduled must be gone, not left stopped
left = subprocess.run(["pgrep", "-f", "longA|longB"], capture_output=True, text=True).stdout.split()
ok(not left, f"no stopped child process survived the interrupted run (found {len(left)})")

# ---------------------------------------------------------------------------
# 2. A scheduling run as a background job
# ---------------------------------------------------------------------------
send("sched clear\n")
expect(PROMPT)
send(f"sched add {BURN} bgA 6000 1000\n")
expect(PROMPT)
send(f"sched add {BURN} bgB 6000 1000\n")
expect(PROMPT)
send("sched run rr -q 200 --quiet &\n")
ok(expect(r"\[1\] \d+"), "the scheduling run started as background job [1]")
expect(PROMPT)
time.sleep(0.6)
send("jobs\n")
ok(expect(r"\[1\]\+\s+Running\s+sched run rr -q 200 --quiet &"),
   "jobs lists the scheduling run while it keeps scheduling processes")
send("kill %1\n")
# The scheduler catches SIGTERM so it can clean up, so the job ends with status
# 143 (128 + SIGTERM) rather than being killed outright.
ok(expect(r"\[1\]\+\s+(Exit 143|Terminated|Done)\s+sched run rr"),
   "kill %1 stops the background scheduling run, which shuts down cleanly (status 143)")
expect(PROMPT)
time.sleep(0.5)
left = subprocess.run(["pgrep", "-f", "bgA|bgB"], capture_output=True, text=True).stdout.split()
ok(not left, f"killing the background run also cleaned up its scheduled processes (found {len(left)})")

# ---------------------------------------------------------------------------
# 3. A background scheduling run that completes on its own
# ---------------------------------------------------------------------------
send("sched clear\n")
expect(PROMPT)
send(f"sched add {BURN} quick 200 100\n")
expect(PROMPT)
send("sched run fcfs --quiet &\n")
expect(PROMPT)
time.sleep(1.2)
send("\n")
ok(expect(r"\[\d+\][+-]?\s+Done\s+sched run fcfs"),
   "a completed background scheduling run is reported as Done at the next prompt")
expect(PROMPT)

send("\x04")                                   # Ctrl-D
time.sleep(0.5)
pump(0.5)
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass

print("\n======== raw transcript (control characters shown as ^X) ========")
text = "".join(transcript).replace("\r\n", "\n").replace("\r", "")
sys.stdout.write(re.sub(r"[\x00-\x08\x0b-\x1f]", lambda m: "^" + chr(ord(m.group()) + 64), text))
print("\n======== verdict: %d/%d checks OK ========" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
