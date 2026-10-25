#!/usr/bin/env python3
"""07_interactive_pty.py - drive myshell through a pseudo-terminal.

Real job control (Ctrl-C, Ctrl-Z, terminal hand-off with tcsetpgrp) only exists
when the shell runs on a terminal, so this demo gives the shell a pty and types
into it the way a user would, including the control characters.  The whole
session is printed as a transcript; the lines starting with '>>>' are verdicts
computed by this script from what the shell actually printed.
"""
import os, pty, re, select, sys, time

SHELL = sys.argv[1] if len(sys.argv) > 1 else "./myshell"
PROMPT = r"myshell:[^\r\n]*\$ $"

pid, fd = pty.fork()
if pid == 0:
    os.environ["PS1"] = ""
    os.execv(SHELL, [SHELL])

transcript, pending = [], ""

def pump(timeout):
    """Read whatever is available within `timeout` seconds into `pending`."""
    global pending
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return False
    try:
        data = os.read(fd, 4096).decode(errors="replace")
    except OSError:
        return False
    transcript.append(data)
    pending += data
    return True

def expect(regex, timeout=6.0):
    """Wait until `regex` matches the unread output; consume up to the match."""
    global pending
    end = time.time() + timeout
    while time.time() < end:
        m = re.search(regex, pending)
        if m:
            pending = pending[m.end():]
            return True
        pump(0.1)
    return False

def send(text, pause=0.0):
    os.write(fd, text.encode())
    if pause:
        time.sleep(pause)

def ok(cond, msg):
    print(f">>> {'OK  ' if cond else 'FAIL'} {msg}")
    return cond

results = []
expect(PROMPT)

# 1. Ctrl-C at an idle prompt must not kill the shell
send("\x03", 0.3)
send("echo prompt-survived-ctrl-c\n")
results.append(ok(expect(r"prompt-survived-ctrl-c\r?\n"), "Ctrl-C at the prompt is ignored by the shell"))
expect(PROMPT)

# 2. Ctrl-Z stops the foreground job and returns to the prompt
send("sleep 30\n", 0.6)
send("\x1a")
stopped = expect(r"\[1\]\+\s+Stopped \(SIGTSTP\)\s+sleep 30")
results.append(ok(stopped, "Ctrl-Z stops the foreground job (Stopped (SIGTSTP))"))
expect(PROMPT)

# 3. jobs / bg / jobs / fg round trip
send("jobs\n")
r1 = expect(r"\[1\]\+\s+Stopped\s+sleep 30")
expect(PROMPT)
send("bg\n")
r2 = expect(r"\[1\]\+ sleep 30 &")
expect(PROMPT)
send("jobs\n")
r3 = expect(r"\[1\]\+\s+Running\s+sleep 30 &")
expect(PROMPT)
send("fg\n", 0.5)
r4 = expect(r"sleep 30\r?\n")
# 4. Ctrl-C now goes to the *foreground job*, not the shell
send("\x03")
expect(PROMPT)
send("echo rc-after-ctrl-c=$?\n")
r5 = expect(r"rc-after-ctrl-c=130")
results.append(ok(r1 and r2 and r3 and r4, "fg/bg round trip OK (Stopped -> bg Running -> fg)"))
results.append(ok(r5, "Ctrl-C killed the foreground job only (status 130); SHELL SURVIVED CTRL-C"))
expect(PROMPT)

# 5. Stop, then fg, let it finish normally
send("sleep 2\n", 0.5)
send("\x1a")
expect(r"Stopped \(SIGTSTP\)")
expect(PROMPT)
send("fg\n")
expect(PROMPT, 8)
send("echo rc-after-fg=$?\n")
results.append(ok(expect(r"rc-after-fg=0"), "stopped job resumed by fg and finished normally (status 0)"))
expect(PROMPT)

# 6. Background job finishing while the shell sits at the prompt
send("sleep 1 &\n")
expect(PROMPT)
time.sleep(1.5)
send("\n")
results.append(ok(expect(r"\[\d+\][+-]?\s+Done\s+sleep 1"), "background completion reported at the next prompt"))
expect(PROMPT)

# 7. Ctrl-D leaves the shell (EOF)
send("\x04")
time.sleep(0.5)
pump(0.5)
try:
    _, status = os.waitpid(pid, 0)
    results.append(ok(os.WIFEXITED(status), "Ctrl-D (EOF) exits the shell cleanly"))
except ChildProcessError:
    pass

print("\n======== raw transcript (control characters shown as ^X) ========")
text = "".join(transcript).replace("\r\n", "\n").replace("\r", "")
print(re.sub(r"[\x00-\x08\x0b-\x1f]", lambda m: "^" + chr(ord(m.group()) + 64), text))
print("\n======== verdict: %d/%d checks OK ========" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
