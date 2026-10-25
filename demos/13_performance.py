#!/usr/bin/env python3
"""13_performance.py - performance analysis of the scheduling algorithms.

Every number below is produced by scheduling REAL processes with the shell's own
`sched` command, so each experiment costs as much real time as the workload
needs.  The workloads are built from demos/cpuburn, a CPU-bound program that
consumes a requested amount of its own CPU time, which makes the offered load
reproducible even though the measurements are of real execution.

  E1  one fixed workload under every policy
  E2  Round-Robin: effect of the time slice
  E3  comparison of the policies on the same workload
  E4  who pays for priority: waiting time per priority class
  E5  cost of context switching
  E6  a CPU-bound and an I/O-bound process together
  E7  accuracy of the quantum timer

usage: 13_performance.py ./myshell ./demos/cpuburn
"""
import os
import re
import statistics as st
import subprocess
import sys
import tempfile

SHELL = sys.argv[1] if len(sys.argv) > 1 else "./myshell"
BURN = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "./demos/cpuburn")
REPS = 3                      # repetitions, to average out system noise
QUANTA = [10, 25, 50, 100, 200, 400]


def run(lines, timeout=300):
    """Run a myshell script and return its output."""
    env = dict(os.environ)
    env["BURN"] = BURN
    with tempfile.NamedTemporaryFile("w", suffix=".msh", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        path = f.name
    try:
        p = subprocess.run([SHELL, path], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout, env=env)
        return p.stdout + p.stderr
    finally:
        os.unlink(path)


def task_rows(text):
    """Per-process rows of a report, parsed from the right so that a command
    containing spaces cannot be confused with the numeric columns."""
    rows = []
    for ln in text.splitlines():
        t = ln.split()
        if len(t) >= 14 and t[-2] in ("exit", "signal") and t[0].isdigit():
            nums = t[-12:-2]           # PRIO ARRIVE START FINISH WAIT BLOCK TURN RESP CPU SLICES
            if not all(x.isdigit() for x in nums):
                continue
            prio, arrive, start, finish, wait, block, turn, resp, cpu, slices = (int(x) for x in nums)
            rows.append(dict(id=int(t[0]), cmd=" ".join(t[1:-12]), prio=prio, arrive=arrive,
                             start=start, finish=finish, wait=wait, block=block, turn=turn, resp=resp,
                             cpu=cpu, slices=slices))
    return rows


def summary(text):
    """The averages / system / switching lines of a report."""
    out = {}
    m = re.search(r"waiting ([\d.]+) ms\s+turnaround ([\d.]+) ms\s+response ([\d.]+) ms", text)
    if m:
        out.update(wait=float(m.group(1)), turn=float(m.group(2)), resp=float(m.group(3)))
    m = re.search(r"makespan (\d+) ms\s+CPU busy (\d+) ms \(([\d.]+)%\)\s+throughput ([\d.]+)", text)
    if m:
        out.update(makespan=int(m.group(1)), busy=int(m.group(2)), cpu=float(m.group(3)),
                   thru=float(m.group(4)))
    m = re.search(r"(\d+) context switches\s+(\d+) preemptions \(SIGSTOP\)\s+(\d+) ms switch overhead\s+(\d+) ms idle", text)
    if m:
        out.update(switches=int(m.group(1)), preempts=int(m.group(2)),
                   overhead=int(m.group(3)), idle=int(m.group(4)))
    return out


def table(headers, rows, widths):
    fmt = "  " + "".join(f"{{:<{w}}}" if i == 0 else f"{{:>{w}}}" for i, w in enumerate(widths))
    print(fmt.format(*headers))
    print("  " + "-" * (sum(widths) - 2))
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))


def head(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def avg(vals):
    return st.mean(vals) if vals else 0.0


# The standard workload: four CPU-bound processes, 820 ms of CPU demand in
# total, two of them arriving after the run has started.
WORKLOAD = [
    ("w1", 300, 9, 0),
    ("w2", 160, 3, 0),
    ("w3", 200, 5, 120),
    ("w4", 160, 1, 260),
]


def adds(workload=None, chunk=1000):
    w = workload if workload is not None else WORKLOAD
    return [f"sched add -p {p} -t {t} $BURN {n} {b} {chunk} > /dev/null" for n, b, p, t in w]


print(__doc__.split("usage:")[0].strip())
print(f"\nshell = {SHELL}\nworkload = " +
      ", ".join(f"{n}: {b} ms cpu, priority {p}, arrives {t} ms" for n, b, p, t in WORKLOAD))
print(f"repetitions per data point = {REPS}")

# ---------------------------------------------------------------- E1
head("E1  One fixed workload under every policy (a single real replay each)")
print(run(adds() + ["sched compare -q 25,100"]).rstrip())

# ---------------------------------------------------------------- E2
head(f"E2  Round-Robin: effect of the time slice ({REPS} real runs per quantum)")
e2 = {}
for q in QUANTA:
    runs = [summary(run(adds() + [f"sched run rr -q {q} --quiet"])) for _ in range(REPS)]
    e2[q] = {k: avg([r.get(k, 0) for r in runs]) for k in ("wait", "turn", "resp", "switches",
                                                           "preempts", "makespan", "cpu")}
table(["quantum (ms)", "avg wait", "avg turn", "avg resp", "switches", "preempts", "makespan", "CPU%"],
      [[q, f"{v['wait']:.0f}", f"{v['turn']:.0f}", f"{v['resp']:.0f}", f"{v['switches']:.1f}",
        f"{v['preempts']:.1f}", f"{v['makespan']:.0f}", f"{v['cpu']:.1f}"] for q, v in e2.items()],
      [14, 10, 10, 10, 10, 10, 10, 8])
best_turn = min(e2, key=lambda q: e2[q]["turn"])
best_resp = min(e2, key=lambda q: e2[q]["resp"])
print(f"  best average turnaround at q={best_turn} ms; best average response at q={best_resp} ms")

# ---------------------------------------------------------------- E3
head(f"E3  The policies compared on the same workload ({REPS} real runs each)")
POLICIES = [("FCFS", "sched run fcfs"),
            ("Round-Robin q=25", "sched run rr -q 25"),
            ("Round-Robin q=100", "sched run rr -q 100"),
            ("Priority, preemptive", "sched run priority"),
            ("Priority, non-preemptive", "sched run priority --no-preempt")]
e3 = {}
for label, cmd in POLICIES:
    runs = [summary(run(adds() + [f"{cmd} --quiet"])) for _ in range(REPS)]
    e3[label] = {k: avg([r.get(k, 0) for r in runs]) for k in ("wait", "turn", "resp", "switches",
                                                               "preempts", "makespan", "cpu")}
table(["policy", "avg wait", "avg turn", "avg resp", "switches", "preempts", "makespan"],
      [[l, f"{v['wait']:.0f}", f"{v['turn']:.0f}", f"{v['resp']:.0f}", f"{v['switches']:.1f}",
        f"{v['preempts']:.1f}", f"{v['makespan']:.0f}"] for l, v in e3.items()],
      [26, 10, 10, 10, 10, 10, 10])

# ---------------------------------------------------------------- E4
head(f"E4  Who pays for priority?  Waiting time by priority class ({REPS} real runs each)")
CLASSES = [("u1", 150, 1, 0), ("u2", 150, 1, 200), ("m1", 150, 5, 50), ("m2", 150, 5, 250),
           ("b1", 150, 9, 0), ("b2", 150, 9, 150)]
print("  six equal-size processes: two urgent (priority 1), two middle (5), two background (9)")
e4 = {}
for label, cmd in POLICIES:
    acc = {"high": [], "mid": [], "low": [], "hresp": []}
    for _ in range(REPS):
        for r in task_rows(run(adds(CLASSES) + [f"{cmd} --quiet"])):
            cls = "high" if r["prio"] <= 2 else ("low" if r["prio"] >= 7 else "mid")
            acc[cls].append(r["wait"])
            if cls == "high":
                acc["hresp"].append(r["resp"])
    e4[label] = acc
table(["policy", "wait high(1)", "wait mid(5)", "wait low(9)", "resp high"],
      [[l, f"{avg(a['high']):.0f}", f"{avg(a['mid']):.0f}", f"{avg(a['low']):.0f}",
        f"{avg(a['hresp']):.0f}"] for l, a in e4.items()],
      [26, 14, 13, 13, 11])

# ---------------------------------------------------------------- E5
head("E5  Cost of context switching (Round-Robin, three 200 ms processes)")
SW = [("s1", 200, 5, 0), ("s2", 200, 5, 0), ("s3", 200, 5, 0)]
rows = []
for q in (25, 100):
    for c in (0, 5, 20):
        s = summary(run(adds(SW) + [f"sched run rr -q {q} -c {c} --quiet"]))
        rows.append([f"q={q}, cost={c} ms", s.get("switches", 0), f"{s.get('overhead', 0)}",
                     s.get("makespan", 0), f"{s.get('cpu', 0):.1f}", f"{s.get('turn', 0):.0f}"])
table(["configuration", "switches", "overhead ms", "makespan", "CPU%", "avg turn"], rows,
      [22, 10, 13, 10, 8, 10])

# ---------------------------------------------------------------- E6
head("E6  A CPU-bound and an I/O-bound process together: block detection on and off")
print("  `sleep 0.5` needs almost no CPU but is not runnable for 500 ms; `busy` needs 300 ms of CPU.")
print("  With block detection the scheduler sees the sleeper block in the kernel and gives the CPU")
print("  away; without it the sleeper holds the CPU while it sleeps, and only a time slice helps.")
rows = []
for label, cmd in (("FCFS, detection on", "sched run fcfs"),
                   ("FCFS, detection off", "sched run fcfs --no-block-detect"),
                   ("RR q=200, detection off", "sched run rr -q 200 --no-block-detect"),
                   ("RR q=50, detection off", "sched run rr -q 50 --no-block-detect"),
                   ("RR q=50, detection on", "sched run rr -q 50")):
    runs = []
    for _ in range(REPS):
        out = run(["sched add sleep 0.5 > /dev/null",
                   "sched add $BURN busy 300 1000 > /dev/null", f"{cmd} --quiet"])
        s = summary(out)
        rs = {r["cmd"].split()[0]: r for r in task_rows(out)}
        runs.append((s.get("makespan", 0), s.get("cpu", 0), rs.get("sleep", {}).get("turn", 0),
                     rs.get("cpuburn", {}).get("turn", 0), rs.get("cpuburn", {}).get("wait", 0),
                     rs.get("sleep", {}).get("block", 0)))
    m = [avg([r[i] for r in runs]) for i in range(6)]
    rows.append([label, f"{m[0]:.0f}", f"{m[1]:.1f}", f"{m[2]:.0f}", f"{m[3]:.0f}", f"{m[4]:.0f}", f"{m[5]:.0f}"])
table(["configuration", "makespan", "CPU%", "sleep turn", "busy turn", "busy wait", "sleep block"], rows,
      [26, 10, 8, 12, 11, 11, 13])

# ---------------------------------------------------------------- E7
head("E7  Accuracy of the quantum timer (measured from the event log)")
rows = []
for q in (20, 50, 200):
    out = run(adds() + [f"sched run rr -q {q}"])
    spans, start = [], None
    for ln in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(DISPATCH|QUANTUM|PREEMPT|FINISH)\b", ln)
        if not m:
            continue
        t, kind = int(m.group(1)), m.group(2)
        if kind == "DISPATCH":
            start = t
        elif start is not None:
            if kind == "QUANTUM":
                spans.append(t - start)
            start = None
    if spans:
        rows.append([f"q={q} ms", len(spans), f"{st.mean(spans):.1f}", min(spans), max(spans),
                     f"{st.mean(spans) - q:+.1f}"])
table(["configured slice", "slices", "mean ms", "min", "max", "mean error"], rows,
      [20, 9, 10, 8, 8, 12])
print("\n  (a slice that ends early is a process finishing or being preempted, so only slices")
print("   that ended in a QUANTUM event are counted here)")
print("\nAll figures above were measured while scheduling real processes.")
