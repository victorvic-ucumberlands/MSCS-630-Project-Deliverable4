#!/usr/bin/env python3
"""verify_schedule.py - check that the shell really behaves like a CPU scheduler.

Because the tasks are real processes, their timings cannot be predicted exactly
and comparing against a precomputed schedule would be meaningless.  What CAN be
checked exactly is that the scheduler obeys its own rules, so this script runs
real workloads through the shell and verifies the properties a CPU scheduler
must have:

  A. MUTUAL EXCLUSION, from the shell's own log: at no event is more than one
     managed process in the Running state.
  B. MUTUAL EXCLUSION, from the kernel: at no event is more than one managed
     process in a runnable kernel state; every queued process is reported as
     'T' (stopped).  The state characters come from /proc, not from the shell.
  C. MUTUAL EXCLUSION, sampled from outside: while a run is in progress this
     script independently polls /proc for the workload's pids and checks the
     same property, so the evidence does not depend on the shell at all.
  D. ROUND-ROBIN ORDER: every dispatch takes the process at the head of the
     FIFO ready queue, and no slice is longer than the configured quantum.
  E. PRIORITY ORDER: every dispatch takes a process whose priority is the best
     (lowest number) in the ready queue, and equal priorities are dispatched in
     arrival order.
  F. PREEMPTION: when a strictly more urgent process arrives while another is
     running, the running one is preempted at that instant.
  G. REAL WORK: the CPU time the kernel charged each cpuburn process matches the
     CPU time that process was asked to consume, which is only possible if the
     scheduled processes really ran.

usage: verify_schedule.py ./myshell ./demos/cpuburn
"""
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

SHELL = sys.argv[1] if len(sys.argv) > 1 else "./myshell"
BURN = sys.argv[2] if len(sys.argv) > 2 else "./demos/cpuburn"

EVENT = re.compile(r"^\s*(\d+)\s+(ARRIVE|DISPATCH|QUANTUM|PREEMPT|FINISH|IDLE|SWITCH|YIELD)\s+(.*?)\s+ready=\[(.*)\]\s*$")
STATE = re.compile(r"^\s+tasks:\s+(.*)$")
TASKROW = re.compile(r"^\s+(\d+)\s+(\S+(?:\s\S+)*?)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(.*)$")

failures = []
checks = 0


def check(ok, msg):
    global checks
    checks += 1
    if ok:
        print(f"  PASS  {msg}")
    else:
        print(f"  FAIL  {msg}")
        failures.append(msg)


def run_shell(lines, timeout=180, env_extra=None):
    env = dict(os.environ)
    env["BURN"] = BURN
    if env_extra:
        env.update(env_extra)
    with tempfile.NamedTemporaryFile("w", suffix=".msh", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        path = f.name
    try:
        p = subprocess.run([SHELL, path], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout, env=env)
        return p.stdout + p.stderr
    finally:
        os.unlink(path)


def parse(text):
    """Return (events, task_rows).  events: list of dicts with the ready queue
    and, when verbose, the per-task state line that follows the event."""
    events, rows = [], []
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        m = EVENT.match(ln)
        if m:
            t, kind, detail, queue = m.groups()
            entries = []
            for tok in ([x for x in queue.split(", ") if x] if queue.strip() else []):
                mm = re.match(r"^(.*?)\((\d+)\)$", tok)
                entries.append((mm.group(1), int(mm.group(2))) if mm else (tok, None))
            ev = {"t": int(t), "kind": kind, "detail": detail, "queue": entries, "states": None}
            if i + 1 < len(lines):
                sm = STATE.match(lines[i + 1])
                if sm:
                    st = {}
                    for tok in sm.group(1).split(", "):
                        k, _, v = tok.rpartition("=")
                        st[k.strip()] = v
                    ev["states"] = st
            events.append(ev)
            continue
        t = ln.split()
        # ID COMMAND... PRIO ARRIVE START FINISH WAIT BLOCK TURN RESP CPU SLICES RESULT(2 words)
        if len(t) >= 14 and t[0].isdigit() and t[-2] in ("exit", "signal") and all(x.isdigit() for x in t[-12:-2]):
            nums = [int(x) for x in t[-12:-2]]
            rows.append({"id": int(t[0]), "cmd": " ".join(t[1:-12]), "prio": nums[0], "cpu": nums[8],
                         "slices": nums[9], "result": " ".join(t[-2:])})
    return events, rows


# The ready-queue column prints labels, which may contain spaces.  Splitting on
# whitespace can therefore merge/split labels, so the workloads below use
# single-token labels (cpuburn is invoked through a symlink per task) to keep
# the parsing unambiguous.
def make_links(tmp, names):
    """Create one symlink to cpuburn per task so each label is a single word."""
    paths = {}
    for n in names:
        p = os.path.join(tmp, n)
        if not os.path.exists(p):
            os.symlink(os.path.abspath(BURN), p)
        paths[n] = p
    return paths


def label_tokens(ev):
    return [name for name, _ in ev["queue"]]


print(f"Verifying the scheduler in {SHELL}\n")
tmp = tempfile.mkdtemp()
names = ["alpha", "bravo", "charlie", "delta", "echo1", "foxtrot"]
links = make_links(tmp, names)

# ===========================================================================
# 1. Round-Robin: FIFO order, slice length, mutual exclusion
# ===========================================================================
print("Round-Robin run (quantum 80 ms, four CPU-bound processes):")
Q = 80
out = run_shell([
    f"sched add {links['alpha']} alpha 240 80",
    f"sched add {links['bravo']} bravo 160 80",
    f"sched add {links['charlie']} charlie 80 40",
    f"sched add {links['delta']} delta 160 80",
    f"sched run rr -q {Q} -v",
])
events, rows = parse(out)
check(len(events) > 10, f"the run produced an event log ({len(events)} events)")
unnamed = [e["t"] for e in events if e["kind"] == "DISPATCH" and not e["detail"].split(":")[0].strip()]
check(not unnamed, "every DISPATCH event names the process it dispatched"
                   + (f" - unnamed at {unnamed[:3]}" if unnamed else ""))

# A. only one task Running at any event (shell's own view)
bad = [e for e in events if e["states"] and sum(1 for v in e["states"].values() if v.startswith("RUN")) > 1]
check(not bad, "A. the shell never has two processes in the Running state at once")

# B. kernel agrees: at most one runnable, all queued ones are 'T'
bad_k, queued_not_T = [], []
for e in events:
    if not e["states"]:
        continue
    runnable = 0
    for name, v in e["states"].items():
        km = re.search(r"kernel (.)", v)
        if not km:
            continue
        k = km.group(1)
        if v.startswith("RUN") and k in "RSD":
            runnable += 1
        if v.startswith("READY") and k != "T":
            queued_not_T.append((e["t"], name, k))
    if runnable > 1:
        bad_k.append(e["t"])
check(not bad_k, "B. the kernel never reports two of our processes runnable at once")
check(not queued_not_T, f"B. every process waiting in the ready queue is stopped ('T') in the kernel"
                        + (f" - offenders: {queued_not_T[:3]}" if queued_not_T else ""))

# D. FIFO order: a dispatched task was the head of the queue at the previous event
viol = []
for i, e in enumerate(events):
    if e["kind"] != "DISPATCH" or i == 0:
        continue
    who = e["detail"].split(":")[0].strip()
    prev = label_tokens(events[i - 1])
    if prev and prev[0] != who:
        viol.append((e["t"], who, prev))
check(not viol, "D. Round-Robin always dispatches the head of the FIFO ready queue"
                + (f" - offenders: {viol[:3]}" if viol else ""))

# D. no slice longer than the quantum (allow 25 ms of real-system slack)
spans, start, cur = [], None, None
for e in events:
    if e["kind"] == "DISPATCH":
        start, cur = e["t"], e["detail"].split(":")[0].strip()
    elif e["kind"] in ("QUANTUM", "PREEMPT", "FINISH") and start is not None:
        spans.append((cur, e["t"] - start))
        start = None
long_slices = [s for s in spans if s[1] > Q + 25]
check(not long_slices, f"D. no process held the CPU longer than the {Q} ms slice"
                       + (f" - longest: {max(spans, key=lambda x: x[1])}" if long_slices else
                          f" (longest observed {max(spans, key=lambda x: x[1])[1]} ms)"))

# G. the processes really ran: charged CPU matches the requested burn
want = {"alpha": 240, "bravo": 160, "charlie": 80, "delta": 160}
off = []
for r in rows:
    nm = r["cmd"].split()[0]
    if nm in want and abs(r["cpu"] - want[nm]) > max(25, 0.2 * want[nm]):
        off.append((nm, r["cpu"], want[nm]))
check(rows and not off, "G. the CPU time the kernel charged each process matches the work it was asked to do"
                        + (f" - off: {off}" if off else ""))
# and a long task must have been sliced several times
alpha = next((r for r in rows if r["cmd"].startswith("alpha")), None)
check(alpha is not None and alpha["slices"] >= 3,
      f"D. the 240 ms process was dispatched in several slices ({alpha['slices'] if alpha else '?'} of {Q} ms)")

# ===========================================================================
# 2. Priority: heap order, FCFS ties, preemption
# ===========================================================================
print("\nPriority run (four priorities, two of them equal):")
out = run_shell([
    f"sched add -p 9 {links['alpha']} alpha 80 40",
    f"sched add -p 1 {links['bravo']} bravo 80 40",
    f"sched add -p 5 {links['charlie']} charlie 80 40",
    f"sched add -p 9 {links['delta']} delta 80 40",
    "sched run priority -v",
])
events, rows = parse(out)
prio, arrival_order = {}, []
for e in events:
    if e["kind"] == "ARRIVE":
        who = e["detail"].split(":")[0].strip()
        mm = re.search(r"prio (\d+)", e["detail"])
        prio[who] = int(mm.group(1)) if mm else 99
        arrival_order.append(who)

# E. every dispatch takes the best priority available
viol = []
for i, e in enumerate(events):
    if e["kind"] != "DISPATCH" or i == 0:
        continue
    who = e["detail"].split(":")[0].strip()
    prev = [(n, p) for n, p in events[i - 1]["queue"] if p is not None]
    if prev:
        best = min(p for _, p in prev)
        if prio.get(who, 99) != best:
            viol.append((e["t"], who, prio.get(who), best))
check(not viol, "E. every dispatch picks the lowest priority number in the heap"
                + (f" - offenders: {viol[:3]}" if viol else ""))

order = [e["detail"].split(":")[0].strip() for e in events if e["kind"] == "DISPATCH"]
check([prio.get(o, 99) for o in order] == sorted(prio.get(o, 99) for o in order),
      f"E. the processes ran in order of increasing priority number: "
      f"{[(o.split()[0], prio.get(o)) for o in order]}")
tied = [o for o in order if prio.get(o) == max(prio.values())]
tied_arrivals = [a for a in arrival_order if prio.get(a) == max(prio.values())]
check(tied == tied_arrivals,
      "E. the two equal-priority processes ran in arrival order (FCFS tie-break)")

# F. preemption at the instant a more urgent process arrives
print("\nPreemption run (a more urgent process is created mid-run):")
out = run_shell([
    f"sched add -p 8 {links['alpha']} alpha 400 100",
    f"sched add -p 4 -t 150 {links['bravo']} bravo 250 50",
    f"sched add -p 0 -t 300 {links['charlie']} charlie 100 50",
    "sched run priority",
])
events, rows = parse(out)
kinds = [(e["t"], e["kind"], e["detail"].split(":")[0].strip()) for e in events]
pre = [k for k in kinds if k[1] == "PREEMPT"]
check(len(pre) >= 2, f"F. the running process was preempted on each urgent arrival ({len(pre)} preemptions)")
# each preemption must follow its arrival immediately (same millisecond scale)
late = []
for i, e in enumerate(events):
    if e["kind"] == "ARRIVE" and i + 1 < len(events):
        nxt = events[i + 1]
        if nxt["kind"] == "PREEMPT" and nxt["t"] - e["t"] > 15:
            late.append((e["t"], nxt["t"]))
check(not late, "F. preemption happens immediately after the arrival (no waiting for a slice)"
                + (f" - delays: {late}" if late else ""))
check(any(r["cmd"].startswith("charlie") and r["slices"] == 1 for r in rows),
      "F. the most urgent process ran to completion in one go once dispatched")
# the low-priority process is pushed to the end, so it finishes last
last_finish = [e["detail"].split(":")[0].strip() for e in events if e["kind"] == "FINISH"]
check(last_finish and last_finish[-1].startswith("alpha"),
      f"F. the low-priority process finished last: {[x.split()[0] for x in last_finish]}")

# non-preemptive variant must show no preemptions
out = run_shell([
    f"sched add -p 8 {links['alpha']} alpha 200 100",
    f"sched add -p 0 -t 80 {links['bravo']} bravo 100 50",
    "sched run priority --no-preempt",
])
events, _ = parse(out)
check(not [e for e in events if e["kind"] == "PREEMPT"],
      "F. --no-preempt never interrupts a running process")

# ===========================================================================
# 3. Mutual exclusion sampled independently from outside the shell
# ===========================================================================
print("\nIndependent sampling of /proc while a run is in progress:")
samples = {"taken": 0, "max_runnable": 0, "seen_pids": set(), "bad": []}
MARK = ["sampletask"]


def sampler(stop_evt):
    while not stop_evt.is_set():
        runnable, pids = 0, []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat") as fh:
                    data = fh.read()
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().decode(errors="replace")
            except OSError:
                continue
            if MARK[0] not in cmd:
                continue
            st = data[data.rfind(")") + 2]
            pids.append((pid, st))
            if st in "RSD":
                runnable += 1
        if pids:
            samples["taken"] += 1
            samples["seen_pids"].update(p for p, _ in pids)
            samples["max_runnable"] = max(samples["max_runnable"], runnable)
            if runnable > 1:
                samples["bad"].append(pids)
        time.sleep(0.01)


links2 = make_links(tmp, ["sampletask1", "sampletask2", "sampletask3"])
stop = threading.Event()
th = threading.Thread(target=sampler, args=(stop,), daemon=True)
th.start()
out = run_shell([
    f"sched add {links2['sampletask1']} s1 300 100",
    f"sched add {links2['sampletask2']} s2 300 100",
    f"sched add {links2['sampletask3']} s3 300 100",
    "sched run rr -q 60 --quiet",
])
stop.set()
th.join(timeout=2)
check(samples["taken"] > 20, f"C. the sampler observed the workload ({samples['taken']} samples, "
                             f"{len(samples['seen_pids'])} processes)")
check(samples["max_runnable"] <= 1,
      f"C. at most one of the three processes was ever runnable (max seen: {samples['max_runnable']})")

# ===========================================================================
# 4. No process is left behind after an interrupted run
# ===========================================================================
print("\nCleanup after an interrupted run:")
with tempfile.NamedTemporaryFile("w", suffix=".msh", delete=False) as f:
    f.write(f"sched add {links['echo1']} echo1 9000 1000\n"
            f"sched add {links['foxtrot']} foxtrot 9000 1000\n"
            "sched run rr -q 100 --quiet\n")
    path = f.name
env = dict(os.environ)
env["BURN"] = BURN
proc = subprocess.Popen([SHELL, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL, env=env)
time.sleep(1.2)
proc.send_signal(2)                      # Ctrl-C
proc.wait(timeout=30)
os.unlink(path)
time.sleep(0.4)
left = subprocess.run(["pgrep", "-f", "echo1|foxtrot"], capture_output=True, text=True).stdout.split()
check(not left, f"cleanup left no stopped or running child behind (found {len(left)})")
check(proc.returncode == 130, f"an interrupted run reports status 130 (got {proc.returncode})")

# ===========================================================================
# 5. Ordinary commands (typed without `sched`) are scheduled with defaults
# ===========================================================================
def jobs_rows(text):
    """Rows of `jobs -a` for finished jobs: REC JOB PID STATE RESULT(2) PRIO TURN WAIT RESP HELD BLOCK CPU SLICES STOPS CMD."""
    rows = []
    for ln in text.splitlines():
        t = ln.split()
        if len(t) >= 16 and t[0].isdigit() and t[4] in ("exit", "sig") and t[6].isdigit():
            rows.append(dict(prio=int(t[6]), turn=int(t[7]), wait=int(t[8]), resp=int(t[9]), held=int(t[10]),
                             block=int(t[11]), cpu=int(t[12]), slices=int(t[13]), cmd=" ".join(t[15:])))
    return rows


def row(rows, word):
    return next((r for r in rows if word in r["cmd"]), None)


print("\nOrdinary commands typed at the prompt (no sched prefix):")
links4 = make_links(tmp, ["livetask1", "livetask2", "livetask3"])
samples.update(taken=0, max_runnable=0, seen_pids=set(), bad=[])
MARK[0] = "livetask"
stop = threading.Event()
th = threading.Thread(target=sampler, args=(stop,), daemon=True)
th.start()
out = run_shell([f"{links4['livetask1']} l1 300 1000 &", f"{links4['livetask2']} l2 300 1000 &",
                 f"{links4['livetask3']} l3 300 1000 &", "sleep 1.3", "jobs -a"])
stop.set()
th.join(timeout=2)
rows = jobs_rows(out)
check(samples["taken"] > 20 and samples["max_runnable"] <= 1,
      f"C. three ordinary background commands: at most one was ever runnable "
      f"(max {samples['max_runnable']} over {samples['taken']} samples)")
check(len([r for r in rows if "livetask" in r["cmd"]]) == 3 and all(r["prio"] == 10 for r in rows if "livetask" in r["cmd"]),
      "every ordinary command was given the default priority 10")
check(all(r["slices"] >= 2 for r in rows if "livetask" in r["cmd"]),
      "they shared the CPU in Round-Robin slices (each was dispatched several times)")

# block detection: a sleeping process does not keep the CPU
out = run_shell(["sleep 1 &", f"{links['alpha']} busyx 300 1000 &", "sleep 1.3", "jobs -a"])
rows = jobs_rows(out)
busy, slp = row(rows, "busyx"), row(rows, "sleep 1 ")
if slp is None:
    slp = next((r for r in rows if r["cmd"].startswith("sleep 1") and "1.3" not in r["cmd"]), None)
check(busy is not None and busy["turn"] < 500,
      f"a CPU-bound command is not held up by a sleeping one started before it "
      f"(turnaround {busy['turn'] if busy else '?'} ms for 300 ms of CPU)")
check(slp is not None and slp["held"] < 60 and slp["block"] > 800,
      f"the sleeping process gave the CPU away (held {slp['held'] if slp else '?'} ms, "
      f"blocked {slp['block'] if slp else '?'} ms)")

# a foreground command competes with a background one
out = run_shell([f"{links['bravo']} hogbg 800 1000 &", f"{links['charlie']} fgx 200 1000", "jobs -a", "kill %1"])
rows = jobs_rows(out)
fgx = row(rows, "fgx")
check(fgx is not None and fgx["slices"] >= 2 and 1.4 * fgx["cpu"] < fgx["turn"] < 3.5 * fgx["cpu"],
      f"a foreground command shares the CPU with a background job (200 ms of CPU, turnaround "
      f"{fgx['turn'] if fgx else '?'} ms in {fgx['slices'] if fgx else '?'} slices)")

# priorities given with prio, and preemption, for ordinary commands
out = run_shell(["sched policy priority", f"{links['delta']} lowx 400 1000 &",
                 f"prio 1 {links['echo1']} urgentx 100 1000 &", "sleep 0.8", "jobs -a"])
rows = jobs_rows(out)
low, urg = row(rows, "lowx"), row(rows, "urgentx")
check(urg is not None and urg["prio"] == 1 and urg["wait"] < 30,
      f"prio 1 COMMAND preempts a running default-priority command at once (waited {urg['wait'] if urg else '?'} ms)")
check(low is not None and low["wait"] >= 80,
      f"the preempted command waited while the urgent one ran ({low['wait'] if low else '?'} ms)")

# contrast: with live scheduling off the kernel runs them in parallel
if (os.cpu_count() or 1) >= 2:
    samples.update(taken=0, max_runnable=0, seen_pids=set(), bad=[])
    MARK[0] = "livetask"
    stop = threading.Event()
    th = threading.Thread(target=sampler, args=(stop,), daemon=True)
    th.start()
    run_shell(["sched live off", f"{links4['livetask1']} o1 400 1000 &", f"{links4['livetask2']} o2 400 1000 &",
               "sleep 0.7"])
    stop.set()
    th.join(timeout=2)
    check(samples["max_runnable"] >= 2,
          f"contrast: with `sched live off` the kernel runs them simultaneously (max {samples['max_runnable']} runnable)")

for n in os.listdir(tmp):
    os.unlink(os.path.join(tmp, n))
os.rmdir(tmp)

print(f"\n{checks - len(failures)}/{checks} scheduler properties verified, {len(failures)} failures")
sys.exit(1 if failures else 0)
