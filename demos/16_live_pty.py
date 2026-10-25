#!/usr/bin/env python3
"""16_live_pty.py - everyday scheduling on a real terminal (pseudo-terminal).

Commands typed at the prompt are scheduled by the shell.  This demo types into
myshell the way a user would and checks the cases that only exist on a
terminal:

  1. Ctrl-Z on a foreground job that is waiting in the ready queue (a more
     urgent job holds the CPU): the shell holds the terminal at that moment,
     catches Ctrl-Z itself and stops the job through the scheduler.
  2. Ctrl-C on such a waiting foreground job: the scheduler gives it the CPU at
     once so it can act on the signal, although a more urgent job is running.
  3. An interactive program (cat) keeps working while a CPU-bound job runs in
     the background: it owns the terminal whenever it is not stopped, and it
     gives the CPU away while it waits for keyboard input (block detection).
  4. Ctrl-C on a foreground job under Round-Robin.

usage: 16_live_pty.py ./myshell ./demos/cpuburn
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


def expect(rx, timeout=8.0):
    global pending
    end = time.time() + timeout
    while time.time() < end:
        m = re.search(rx, pending)
        if m:
            pending = pending[m.end():]
            return True
        pump(0.05)
    return False


def send(s, pause=0.0):
    os.write(fd, s.encode())
    time.sleep(pause)


results = []


def ok(c, m):
    print(f">>> {'OK  ' if c else 'FAIL'} {m}")
    results.append(c)


expect(PROMPT)

# 1 + 2: a foreground job stuck behind a more urgent background job
send("sched policy priority\n"); expect(PROMPT)
send(f"prio 1 {BURN} hog 5000 1000 &\n"); expect(PROMPT)
send(f"{BURN} fgjob 500 100\n", 0.6)          # priority 10: waits in the ready queue
t0 = time.time()
send("\x1a")                                    # Ctrl-Z
stopped = expect(r"Stopped \(SIGTSTP\)\s+\S*cpuburn fgjob", 3)
ok(stopped, f"Ctrl-Z stops a foreground job that is waiting in the ready queue ({time.time() - t0:.2f}s)")
expect(PROMPT)
send("sched ps\n")
ok(expect(r"STOPPED\s+T\s+.*cpuburn fgjob", 3), "sched ps shows it STOPPED (taken out of the ready queue)")
expect(PROMPT)
send("fg\n", 0.6)
t1 = time.time()
send("\x03")                                    # Ctrl-C while it waits behind the hog
back = expect(PROMPT, 3)
dt = time.time() - t1
ok(back and dt < 1.0, f"Ctrl-C ends it at once although a more urgent job holds the CPU ({dt:.2f}s)")
send("echo rc=$?\n")
ok(expect(r"rc=130"), "the foreground job's status is 130 (killed by SIGINT)")
expect(PROMPT)

# 3: interactive program beside a CPU hog, under Round-Robin
send("sched policy rr\n"); expect(PROMPT)
send("cat\n", 0.5)
t2 = time.time()
send("typed while a CPU hog runs\n")
echoed = expect(r"typed while a CPU hog runs\r?\n(?:.*\r?\n)?.*typed while a CPU hog runs", 3)
ok(echoed, f"cat echoes keyboard input while a CPU-bound job runs ({time.time() - t2:.2f}s)")
send("\x04")                                    # Ctrl-D ends cat
ok(expect(PROMPT, 3), "Ctrl-D ends cat")

# 4: Ctrl-C on a Round-Robin foreground job
send(f"{BURN} fg2 4000 1000\n", 0.7)
send("\x03")
ok(expect(PROMPT, 3), "Ctrl-C ends a foreground job under Round-Robin")
send("echo rc=$?\n")
ok(expect(r"rc=130"), "status 130")
expect(PROMPT)

send("jobs\n"); expect(PROMPT)
send("kill %1\n"); expect(PROMPT)
time.sleep(0.3)
left = subprocess.run(["pgrep", "-f", "cpuburn (hog|fgjob|fg2)"], capture_output=True, text=True).stdout.split()
ok(not left, f"no scheduled process is left behind (found {len(left)})")
send("\x04")
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
