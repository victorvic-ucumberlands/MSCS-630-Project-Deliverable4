#!/usr/bin/env python3
"""verify_memory.py - property checks of the shell's memory manager and
synchronization primitives (Deliverable 3), on real processes.

The page-replacement checks compare the shell against an INDEPENDENT reference
implementation of FIFO, LRU, Clock and OPT written here in Python; the
synchronization checks look at results the processes cannot fake (the final
value of a shared counter, a log of every consumed item, the order in which
sleepers were woken, the kernel's own process states).

usage: verify_memory.py ./myshell ./demos
"""
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time

SHELL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./myshell")
DEMOS = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "./demos")
results = []


def check(ok, what):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + what)
    sys.stdout.flush()


def run(lines, timeout=300, sampler=None):
    env = dict(os.environ)
    env["DEMOS"] = DEMOS
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, "s.msh")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        p = subprocess.Popen([SHELL, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=work,
                             stdin=subprocess.DEVNULL, env=env)
        th = None
        if sampler:
            th = threading.Thread(target=sampler, args=(p.pid,))
            th.start()
        out, _ = p.communicate(timeout=timeout)
        if th:
            th.join()
        return out


# ---------------------------------------------------------------------------
# Reference implementation of the replacement policies
# ---------------------------------------------------------------------------
def ref_sim(refs, writes, nframes, policy):
    frames = [None] * nframes
    loaded = [0] * nframes
    used = [0] * nframes
    refbit = [False] * nframes
    dirty = [False] * nframes
    hand = 0
    faults = writebacks = 0
    for t, page in enumerate(refs):
        if page in frames:
            at = frames.index(page)
        else:
            faults += 1
            if None in frames:
                at = frames.index(None)
            else:
                if policy == "FIFO":
                    at = min(range(nframes), key=lambda f: loaded[f])
                elif policy == "LRU":
                    at = min(range(nframes), key=lambda f: used[f])
                elif policy == "Clock":
                    while refbit[hand]:
                        refbit[hand] = False
                        hand = (hand + 1) % nframes
                    at = hand
                    hand = (hand + 1) % nframes
                else:  # OPT: the page used furthest in the future (never again = first, lowest frame)
                    def nxt(f):
                        for u in range(t + 1, len(refs)):
                            if refs[u] == frames[f]:
                                return u
                        return len(refs) + (nframes - f)
                    at = max(range(nframes), key=nxt)
                writebacks += dirty[at]
            frames[at] = page
            loaded[at] = t + 1
            dirty[at] = False
        used[at] = t + 1
        refbit[at] = True
        if writes[t]:
            dirty[at] = True
    return faults, writebacks


def fmt(refs, writes):
    return ",".join(f"{p}{'w' if w else ''}" for p, w in zip(refs, writes))


def sim_out(text):
    return {m.group(1): (int(m.group(2)), int(m.group(3)))
            for m in re.finditer(r"^\s+(FIFO|LRU|Clock|OPT)\s+(\d+) page faults.*write-backs (\d+)", text, re.M)}


def memproc(text, name):
    m = re.search(rf"^{name}: (\d+) references, (\d+) page faults \((\d+) minor, (\d+) major\).*data check (\S+)", text, re.M)
    return m.groups() if m else None


print(__doc__.split("usage:")[0].strip())
print()
rng = random.Random(2026)

# 1. mem sim against the reference implementation ------------------------------
cases, bad = 0, []
lines = []
specs = []
for i in range(40):
    n = rng.randint(1, 60)
    pages = rng.randint(1, 10)
    refs = [rng.randrange(pages) for _ in range(n)]
    writes = [rng.random() < 0.3 for _ in range(n)]
    f = rng.randint(1, 8)
    specs.append((refs, writes, f))
    lines += [f"echo CASE {i}", f"mem sim -a all -f {f} {fmt(refs, writes)} -q"]
out = run(lines)
parts = re.split(r"^CASE (\d+)$", out, flags=re.M)
got = {int(parts[i]): sim_out(parts[i + 1]) for i in range(1, len(parts) - 1, 2)}
for i, (refs, writes, f) in enumerate(specs):
    for pol in ("FIFO", "LRU", "Clock", "OPT"):
        cases += 1
        if got.get(i, {}).get(pol) != ref_sim(refs, writes, f, pol):
            bad.append((i, pol))
check(not bad and cases == 160, f"mem sim agrees with an independent FIFO/LRU/Clock/OPT implementation ({cases} cases: faults and write-backs)")

# 2. live processes against the reference ---------------------------------------
bad = []
lines = ["mem config -f 5 -s 64 -d 0"]
specs = []
for i in range(6):
    n = rng.randint(50, 300)
    pages = rng.randint(4, 12)
    refs = [rng.randrange(pages) for _ in range(n)]
    writes = [rng.random() < 0.4 for _ in range(n)]
    for pol in ("fifo", "lru", "clock"):
        specs.append((i, pol, refs, writes, pages))
        lines += [f"mem policy {pol}", f"$DEMOS/memproc L{i}{pol} {pages} {fmt(refs, writes)}", f"mem ps -a"]
out = run(lines)
wb = {}
for ln in out.splitlines():
    t = ln.split()
    if len(t) > 12 and t[0].isdigit() and t[1].startswith("L"):
        wb[t[1]] = int(t[11])
for i, pol, refs, writes, pages in specs:
    r = memproc(out, f"L{i}{pol}")
    exp = ref_sim(refs, writes, 5, {"fifo": "FIFO", "lru": "LRU", "clock": "Clock"}[pol])
    if not r or int(r[1]) != exp[0] or wb.get(f"L{i}{pol}") != exp[1] or r[4] != "OK":
        bad.append((i, pol, r, exp, wb.get(f"L{i}{pol}")))
check(not bad, f"live processes: page faults and write-backs equal the reference for {len(specs)} runs (FIFO, LRU, Clock)")

# 3. Belady's anomaly, live ---------------------------------------------------------
out = run(["mem policy fifo", "mem config -f 3", "$DEMOS/memproc b3 6 1,2,3,4,1,2,5,1,2,3,4,5",
           "mem config -f 4", "$DEMOS/memproc b4 6 1,2,3,4,1,2,5,1,2,3,4,5"])
b3, b4 = memproc(out, "b3"), memproc(out, "b4")
check(b3 and b4 and int(b3[1]) == 9 and int(b4[1]) == 10, "Belady's anomaly on a live process: FIFO gives 9 faults with 3 frames, 10 with 4")

# 4. data integrity under pressure, and no leaks -------------------------------------
cmd = " & ".join(f"$DEMOS/memproc d{i} 4 rand:600:4:{i}:50 -s 0" for i in range(8)) + " &"
cmd2 = " & ".join(f"$DEMOS/memproc e{i} 3 loop:3:100 -W -s 1" for i in range(6)) + " &"
out = run(["mem config -f 4 -s 64", "mem policy lru", cmd, cmd2, "sleep 4", "mem", "mem shm"])
oks = [memproc(out, f"d{i}") for i in range(8)] + [memproc(out, f"e{i}") for i in range(6)]
major = sum(int(o[3]) for o in oks if o)
check(all(o and o[4] == "OK" for o in oks) and major > 100,
      f"14 processes on 4 frames: every value read back is the value written ({major} pages read back from swap)")
check("Frames: 0 used, 4 free" in out and "committed 0 of" in out and "swap slots in use 0" in out,
      "after they exit every frame, page and swap slot is free again (no leak)")

# 5. the frame table and the page tables agree ---------------------------------------
out = run(["mem config -f 4 -s 16", "$DEMOS/memproc A 3 0w,1,2w --hold 500 & $DEMOS/memproc B 3 0,1w --hold 500 &",
           "sleep 0.25", "mem frames", "mem pt %1", "mem pt %2", "sleep 0.5"])
frames = dict(re.findall(r"^\s+(\d+)\s+([AB]:\d+)\s+(?:dirty|clean)", out, re.M))
pts = {}
for who in ("A", "B"):
    sec = out.split(f"Page table of {who} ")[1].split("myshell")[0] if f"Page table of {who} " in out else ""
    for vp, fr in re.findall(r"^\s+(\d+)\s+private\s+resident\s+(\d+)", sec, re.M):
        pts[fr] = f"{who}:{vp}"
check(frames and frames == pts, f"every resident page is in exactly the frame the frame table says ({len(frames)} frames checked)")

# 6. a page fault with swap I/O blocks the process and the CPU goes elsewhere ----------
out = run(["mem config -f 2 -s 16 -d 30", "sched trace on",
           "$DEMOS/memproc slow 4 0w,1w,2w,3w,0,1,2,3 & $DEMOS/cpuburn busy 100 100 &", "sleep 1.2", "sched trace off"])
blk = re.search(r"BLOCK\s+memproc slow~?.*?waits for page I/O", out)
nxt = re.search(r"BLOCK\s+memproc slow.*\n.*DISPATCH cpuburn busy", out)
check(bool(blk) and bool(nxt), "a process waiting for page I/O is BLOCKED and the CPU is dispatched to another process")

# 7. mutual exclusion -------------------------------------------------------------------
lost = 0
for rep in range(3):
    out = run(["$DEMOS/counter --reset v", "$DEMOS/counter A 20000 --seg v & $DEMOS/counter B 20000 --seg v &",
               "sleep 6", "$DEMOS/counter --show v"])
    m = re.search(r"counter in v = (\d+)", out)
    if m and int(m.group(1)) < 40000:
        lost += 1
check(lost >= 1, f"without synchronization updates are lost (in {lost} of 3 runs the total was below 40000)")
exact = True
for opt in ("--lock vm", "--sem vs"):
    cmd = " & ".join(f"$DEMOS/counter C{i} 1500 --seg v {opt}" for i in range(4)) + " &"
    out = run(["$DEMOS/counter --reset v", cmd, "sleep 6", "$DEMOS/counter --show v"])
    m = re.search(r"counter in v = (\d+)", out)
    exact = exact and bool(m) and int(m.group(1)) == 6000
check(exact, "with a mutex, and with a binary semaphore, 4 x 1500 increments give exactly 6000")

# 8. FIFO wake-up order ------------------------------------------------------------------
out = run(["$DEMOS/mktest fifo 10"])
check("FIFO order kept" in out, "10 sleepers on one semaphore are woken in exactly the order they went to sleep")

# 9. a waiting process really sleeps -------------------------------------------------------
states = []


def sampler(shell_pid):
    deadline = time.time() + 2.5
    while time.time() < deadline:
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                with open(f"/proc/{pid}/stat") as f:
                    s = f.read()
                if "(counter)" in s:
                    st_ = s.rsplit(")", 1)[1].split()
                    states.append((st_[0], int(st_[11])))     # state, utime
        except Exception:
            pass
        time.sleep(0.01)


out = run(["sem create sleepy 0", "$DEMOS/counter S 1 --seg z --sem sleepy &", "sleep 0.3", "sched ps",
           "sleep 1.5", "sem post sleepy", "sleep 0.3"], sampler=sampler)
asleep = [s for s in states if s[0] == "S"]
check("BLOCKED" in out and "waits for semaphore 'sleepy'" in out and len(asleep) > 50 and
      len({u for _, u in asleep}) <= 2,
      f"a process waiting on a semaphore is BLOCKED, asleep in the kernel ({len(asleep)} samples in state S) and uses no CPU")

# 10. producer-consumer -----------------------------------------------------------------------
cmd = " & ".join([f"$DEMOS/pc producer {i} 300" for i in (1, 2, 3)] + [f"$DEMOS/pc consumer {i} 300" for i in (1, 2, 3)]) + " &"
out = run(["$DEMOS/pc init 5", cmd, "sleep 6", "$DEMOS/pc check pc.log 3 300", "sem"])
empty = re.search(r"^\s+buf\.empty\s+semaphore\s+(\d+)", out, re.M)
full = re.search(r"^\s+buf\.full\s+semaphore\s+(\d+)", out, re.M)
check("CORRECT" in out and empty and full and int(empty.group(1)) == 5 and int(full.group(1)) == 0,
      "3 producers x 3 consumers: every item exactly once, in order; afterwards empty = 5 and full = 0")
out = run(["$DEMOS/pc init 3", "$DEMOS/pc producer 1 60 -v & $DEMOS/pc producer 2 60 -v & $DEMOS/pc consumer 1 120 -v -t 2 &",
           "sleep 3", "$DEMOS/pc check pc.log 2 60"])
fills = [(int(a), int(b)) for a, b in re.findall(r"\(buffer (-?\d+)/(\d+)\)", out)]
check(fills and all(0 <= a <= b for a, b in fills) and "CORRECT" in out,
      f"the buffer never holds more than N or fewer than 0 items ({len(fills)} puts/gets checked)")
cmd = " & ".join([f"$DEMOS/pc producer {i} 400 --nosync" for i in (1, 2)] + [f"$DEMOS/pc consumer {i} 400 --nosync" for i in (1, 2)]) + " &"
out = run(["$DEMOS/pc init 8", "sched live off", cmd, "sleep 4", "$DEMOS/pc check pc.log 2 400"])
check("WRONG" in out, "the same buffer without semaphores loses or duplicates items")

# 11. dining philosophers ----------------------------------------------------------------------
naive = " & ".join(f"$DEMOS/philo {i} 5 2 --naive --pause 100" for i in range(5)) + " &"
out = run([naive, "sleep 1.5", "sem deadlock", "kill %1 %2 %3 %4 %5", "sleep 0.3"])
cyc = re.search(r"DEADLOCK detected \(5 processes in a cycle\)", out)
check(bool(cyc) and all(f"holds fork{i}" in out for i in range(5)), "naive philosophers deadlock and the shell names the whole 5-process cycle")
ok = True
for mode in ("ordered", "waiter"):
    for rep in range(3):
        cmd = " & ".join(f"$DEMOS/philo {i} 5 4 --{mode} --pause 30 --think 5 --eat 5" for i in range(5)) + " &"
        out = run([cmd, "sleep 4", "jobs"])
        ok = ok and len(re.findall(r"finished 4 meals", out)) == 5 and "DEADLOCK" not in out
check(ok, "ordered forks and a waiter: 6 runs, never a deadlock, every philosopher eats every meal")
cmd = " & ".join(f"$DEMOS/philo {i} 5 2 --naive --pause 100" for i in range(5)) + " &"
out = run(["sem config --deadlock fail", cmd, "sleep 4"])
check(len(re.findall(r"finished 2 meals", out)) == 5 and "refused" in out,
      "with --deadlock fail the shell refuses the lock that closes the cycle and the naive philosophers recover")

# 12. robust mutex and the API -------------------------------------------------------------------
out = run(["$DEMOS/mktest hold rr 5000 & $DEMOS/mktest lock rr &", "sleep 0.3", "kill -9 %1", "sleep 0.3"])
check("previous owner died holding it" in out, "a mutex whose owner is killed is released and the next owner is told")
out = run(["$DEMOS/mktest api", "$DEMOS/mktest garbage", "$DEMOS/mktest twice"])
check("all cases behaved as specified" in out and "closed the connection (as it should)" in out and "refused (as it should)" in out,
      "every kernel request with bad arguments is refused with the right error; malformed requests drop the connection")

# 13. one CPU: memory processes are scheduled like any others --------------------------------------
maxr = [0]


def sampler2(shell_pid):
    deadline = time.time() + 2.0
    while time.time() < deadline:
        r = 0
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat") as f:
                    s = f.read()
            except Exception:
                continue
            if "(memproc)" in s and s.rsplit(")", 1)[1].split()[0] == "R":
                r += 1
        maxr[0] = max(maxr[0], r)
        time.sleep(0.005)


cmd = " & ".join(f"$DEMOS/memproc r{i} 4 loop:4:2000 -c 20" for i in range(3)) + " &"
out = run(["mem config -f 8", cmd, "sleep 2.2"], sampler=sampler2)
check(maxr[0] <= 1 and all(memproc(out, f"r{i}") for i in range(3)),
      f"three memory-using processes: at most one was ever runnable at a time (max seen {maxr[0]})")

print()
print(f"{sum(results)} of {len(results)} properties hold")
sys.exit(0 if all(results) else 1)
