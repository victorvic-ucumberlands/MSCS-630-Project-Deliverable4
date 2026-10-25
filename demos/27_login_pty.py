#!/usr/bin/env python3
"""27_login_pty.py - user authentication on a real terminal (Deliverable 4).

Runs ./myshell on a pseudo-terminal exactly as a person would use it: the
login prompt, a password that is not echoed, wrong passwords, an unknown user,
the account lock after five failures, logout and a second user, switching user
with `login`, adding a user and changing a password.  The whole session is
printed (passwords never appear, because the terminal does not echo them),
followed by PASS/FAIL checks.

usage: 27_login_pty.py ./myshell      (uses its own fresh user database)
"""
import os
import pty
import re
import select
import subprocess
import sys
import tempfile
import time

SHELL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./myshell")
work = tempfile.mkdtemp()
env = dict(os.environ, MYSHELL_HOME=work + "/.myshell", MYSHELL_FS=work + "/fs", TERM="dumb")
env.pop("MYSHELL_PASSWORD", None)
subprocess.run([SHELL, "--setup-demo"], env=env, stdout=subprocess.DEVNULL, check=True)

results = []


def check(ok, what):
    results.append((ok, what))


class Term:
    def __init__(self):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(work)
            os.execve(SHELL, [SHELL], env)
        self.out = ""

    def read(self, until=None, timeout=4.0):
        end = time.time() + timeout
        start = len(self.out)
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                self.out += data.decode(errors="replace").replace("\r", "")
                if until and re.search(until, self.out[start:]):
                    return True
        return until is None

    def send(self, text, until=None, timeout=4.0):
        os.write(self.fd, text.encode())
        return self.read(until, timeout)

    def close(self):
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass


PROMPT = r"myshell:[^\n]*[$#] $"
t = Term()
t.read(r"login: ")
check("please log in" in t.out, "the shell asks for a login before anything else")
# a wrong password, then an unknown user: the same answer, so names cannot be probed
t.send("alice\n", r"password: ")
t.send("not-her-password\n", r"login: ", 6)
t.send("mallory\n", r"password: ")
t.send("whatever1\n", r"login: ", 6)
check(t.out.count("Login incorrect") == 2, "a wrong password and an unknown user get the same 'Login incorrect'")
check("not-her-password" not in t.out and "whatever1" not in t.out, "passwords are never echoed")
t.send("alice\n", r"password: ")
t.send("alice123\n", PROMPT)
check(re.search(r"Welcome, alice \(role standard, group users\)", t.out) is not None, "alice logs in (role standard)")
check("1 failed login attempt" in t.out, "she is told about the failed attempt since her last login")
check("alice@myshell:~$ " in t.out, "the prompt shows the user; she starts in her home directory")
t.send("whoami\n", PROMPT)
t.send("id\n", PROMPT)
t.send("pwd\n", PROMPT)
t.send("cat ~/notes.txt\n", PROMPT)
t.send("cat ../../system/secret.key\n", PROMPT)
check("cat: ../../system/secret.key: permission denied" in t.out and "SECRET-KEY" not in t.out,
      "alice may not read the system secret")
# switch user inside the session (like su): bob
t.send("login bob\n", r"password: ")
t.send("bob12345\n", PROMPT)
check("bob@myshell:~$ " in t.out, "login bob switches the session to bob")
t.send("logout\n", r"login: ")
check("bob logged out" in t.out, "logout ends the session and shows the login prompt again")
# admin
t.send("admin\n", r"password: ")
t.send("admin123\n", PROMPT)
check("admin@myshell:~# " in t.out, "admin gets the '#' prompt")
t.send("users\n", PROMPT)
# add a user (the password is typed twice and checked)
t.send("useradd carol\n", r"new password: ")
t.send("short\n", r"retype new password: ")
t.send("short\n", PROMPT)
check("at least 8 characters" in t.out, "a weak password is refused")
t.send("useradd carol\n", r"new password: ")
t.send("carol2026\n", r"retype new password: ")
t.send("carol2027\n", PROMPT)
check("passwords do not match" in t.out, "two different passwords are refused")
t.send("useradd carol\n", r"new password: ")
t.send("carol2026\n", r"retype new password: ")
t.send("carol2026\n", PROMPT)
check("user 'carol' added (role standard" in t.out, "admin adds carol")
t.send("logout\n", r"login: ")
# carol logs in, changes her password
t.send("carol\n", r"password: ")
t.send("carol2026\n", PROMPT)
check("Welcome, carol" in t.out, "the new user can log in")
t.send("passwd\n", r"current password: ")
t.send("carol2026\n", r"new password: ")
t.send("carolNew99\n", r"retype new password: ")
t.send("carolNew99\n", PROMPT)
check("password for 'carol' changed" in t.out, "carol changes her own password")
t.send("logout\n", r"login: ")
t.send("carol\n", r"password: ")
t.send("carol2026\n", r"login: ", 6)
t.send("carol\n", r"password: ")
t.send("carolNew99\n", PROMPT)
check(t.out.rstrip().endswith("carol@myshell:~$"), "the old password no longer works, the new one does")
t.send("logout\n", r"login: ")
# five wrong passwords lock bob's account (three per session, then a new shell)
t.send("bob\n", r"password: ")
t.send("wrong1\n", r"login: ", 6)
t.send("bob\n", r"password: ")
t.send("wrong2\n", r"login: ", 6)
t.send("bob\n", r"password: ")
t.send("wrong3\n", None, 6)
t.read(None, 2)
check("too many failed attempts" in t.out, "three failures in a row end the login session")
t.close()
t2 = Term()
t2.read(r"login: ")
t2.send("bob\n", r"password: ")
t2.send("wrong4\n", r"login: ", 6)
t2.send("bob\n", r"password: ")
t2.send("wrong5\n", r"login: ", 6)
t2.send("bob\n", r"password: ")
t2.send("bob12345\n", r"login: ", 6)
check("account 'bob' is locked" in t2.out, "after five failures even the right password is refused: the account is locked")
t2.read(None, 2)
t2.close()
lockout = t2.out
t2 = Term()                       # a fresh login session for the administrator
t2.read(r"login: ")
t2.send("admin\n", r"password: ")
t2.send("admin123\n", PROMPT)
t2.send("users\n", PROMPT)
check(re.search(r"bob\s+standard\s+users\s+5\s+yes", t2.out) is not None, "admin sees bob's 5 failures and the lock")
t2.send("unlock bob\n", PROMPT)
t2.send("audit 12\n", PROMPT)
check("LOCK bob" in t2.out and "UNLOCK bob by admin" in t2.out, "the audit log records the lock and the unlock")
t2.send("login bob\n", r"password: ")
t2.send("bob12345\n", PROMPT)
check("bob@myshell:~$ " in t2.out, "after the unlock bob can log in again")
t2.send("exit\n", None, 2)
t2.close()
# guest
t3 = Term()
t3.read(r"login: ")
t3.send("guest\n", r"password: ")
t3.send("guest123\n", PROMPT)
t3.send("touch note.txt\n", PROMPT)
check("role guest is read-only" in t3.out, "a guest can log in but may not create files")
t3.send("exit\n", None, 2)
t3.close()

print(__doc__.split("usage:")[0].strip())
print("\n======== session 1 ========\n" + t.out)
print("\n======== session 2 (bob's account is locked) ========\n" + lockout)
print("\n======== session 3 (admin unlocks it) ========\n" + t2.out)
print("\n======== session 4 (guest) ========\n" + t3.out)
print("\n======== checks ========")
for ok, what in results:
    print(("OK   " if ok else "FAIL ") + what)
print(f"{sum(ok for ok, _ in results)} of {len(results)} checks passed")
sys.exit(0 if all(ok for ok, _ in results) else 1)
