#!/usr/bin/env python3
"""24_memory_perf.py - performance analysis of paging and synchronization.

Every live number below comes from real processes started by the shell: the
memory references go through the shell's page tables, page faults are handled
and pages replaced by the shell, and the semaphores are the shell's.  The
offline figures come from `mem sim`, which replays the same reference strings.

  M1  page faults against the number of frames (offline, three workloads)
  M2  live processes against the offline replay (they must agree exactly)
  M3  multiprogramming: more processes sharing the frames -> thrashing
  M4  the replacement policies on the live multiprogrammed workload
  M5  demand paging: memory a process is given against memory it uses
  S1  the cost of mutual exclusion (shared counter)
  S2  producer-consumer: effect of the buffer size
  S3  dining philosophers: ordered forks against a waiter

usage: 24_memory_perf.py ./myshell ./demos
"""
import os
import re
import statistics as st
import subprocess
import sys
import tempfile

SHELL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./myshell")
DEMOS = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "./demos")
REPS = 3


def run(lines, timeout=300):
    env = dict(os.environ)
    env["DEMOS"] = DEMOS
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, "s.msh")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        p = subprocess.run([SHELL, path], capture_output=True, text=True, cwd=work,
                           stdin=subprocess.DEVNULL, timeout=timeout, env=env)
        return p.stdout + p.stderr


def head(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def table(headers, rows, widths):
    fmt = "  " + "".join("{:>%d}" % w for w in widths)
    print(fmt.format(*headers))
    print("  " + "-" * (sum(widths) - 2))
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))


def sim_faults(text):
    """{policy: faults} from `mem sim -q` output."""
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^\s+(FIFO|LRU|Clock|OPT)\s+(\d+) page faults", text, re.M)}


def sim_range(text):
    """[(frames, {policy: faults})] from a `mem sim -f A-B` table."""
    rows = []
    hdr = None
    for ln in text.splitlines():
        t = ln.split()
        if t[:1] == ["FRAMES"]:
            hdr = t[1:]
        elif hdr and len(t) == len(hdr) + 1 and all(x.isdigit() for x in t):
            rows.append((int(t[0]), dict(zip(hdr, map(int, t[1:])))))
    return rows


def memproc_lines(text):
    """{name: (refs, faults, minor, major, peak)} from memproc summary lines."""
    out = {}
    for m in re.finditer(r"^(\S+): (\d+) references, (\d+) page faults \((\d+) minor, (\d+) major\).*?peak resident (\d+) of (\d+)", text, re.M):
        out[m.group(1)] = tuple(int(m.group(i)) for i in range(2, 8))
    return out


def sched_summary(text):
    m = re.search(r"makespan (\d+) ms\s+CPU busy (\d+) ms \(([\d.]+)%\)", text)
    b = re.search(r"(\d+) context switches.*?(\d+) blocks", text)
    return (int(m.group(1)), float(m.group(3)), int(b.group(1)), int(b.group(2))) if m and b else None


print(__doc__.split("usage:")[0].strip())
print(f"\nshell = {SHELL}\nrepetitions per live data point = {REPS}")

# ---------------------------------------------------------------------------
head("M1  Page faults against the number of frames (offline replay of each string)")
WORK = [("locality", "local:3000:40:8:{s}:30", "3000 references to 40 pages, 90% inside a moving working set of 8"),
        ("random", "rand:3000:24:{s}:30", "3000 uniformly random references to 24 pages"),
        ("loop", "loop:12:250", "a sequential scan of 12 pages, 250 times")]
M1 = {}
for name, spec, desc in WORK:
    print(f"\n  {name}: {desc}  (mean of 3 seeds where random)")
    acc = {}
    seeds = [1, 2, 3] if "{s}" in spec else [0]
    for s in seeds:
        for f, d in sim_range(run([f"mem sim -a all -f 2-16 {spec.format(s=s)}"])):
            for p, v in d.items():
                acc.setdefault(f, {}).setdefault(p, []).append(v)
    rows = []
    for f in sorted(acc):
        rows.append([f] + [round(st.mean(acc[f][p])) for p in ("FIFO", "LRU", "Clock", "OPT")])
    M1[name] = rows
    table(["frames", "FIFO", "LRU", "Clock", "OPT"], [r for r in rows if r[0] in (2, 4, 6, 8, 10, 12, 14, 16)],
          [8, 8, 8, 8, 8])
loc = {r[0]: r for r in M1["locality"]}
print(f"\n  locality, 8 frames: FIFO {loc[8][1]}, LRU {loc[8][2]}, Clock {loc[8][3]}, OPT {loc[8][4]} faults"
      f"  -> LRU saves {100 * (loc[8][1] - loc[8][2]) / loc[8][1]:.0f}% of FIFO's faults")
lp = {r[0]: r for r in M1["loop"]}
print(f"  loop of 12 pages, 11 frames: FIFO {lp[11][1]}, LRU {lp[11][2]}, OPT {lp[11][4]} faults"
      f"  (LRU's worst case: every reference faults); 12 frames: {lp[12][2]}")

# ---------------------------------------------------------------------------
head("M2  Live processes against the offline replay")
rows = []
for spec, pages, nf in [("local:2000:20:6:5:30", 20, 6), ("rand:2000:12:5:30", 12, 6),
                        ("7,0,1,2,0,3,0,4,2,3,0,3,2,1,2,0,1,7,0,1", 8, 3)]:
    off = sim_faults(run([f"mem sim -a all -f {nf} {spec} -q"]))
    for pol in ("fifo", "lru", "clock"):
        out = run([f"mem config -f {nf} -s 64", f"mem policy {pol}", f"$DEMOS/memproc live {pages} {spec}"])
        live = memproc_lines(out).get("live")
        key = {"fifo": "FIFO", "lru": "LRU", "clock": "Clock"}[pol]
        lf = live[1] if live else -1
        short = spec if len(spec) < 22 else spec[:19] + "..."
        rows.append([short, nf, key, off.get(key), lf, "yes" if lf == off.get(key) else "DIFFERENT"])
table(["reference string", "frames", "policy", "offline", "live", "equal"], rows, [24, 8, 8, 9, 7, 7])
print("  (the live manager and the offline simulator are separate implementations)")

# ---------------------------------------------------------------------------
head("M3  Multiprogramming: k processes share 16 frames (LRU, 3 ms swap I/O, RR q=20)")
print("  each process: 600 references with locality to 24 pages (working set 6), 50 us of CPU")
print("  work per reference; all k are created at once by `sched run`")
M3 = []
for k in (1, 2, 3, 4, 5, 6):
    vals = []
    for rep in range(REPS):
        lines = ["mem config -f 16 -s 256 -d 3", "mem policy lru", "sched clear"]
        for i in range(k):
            lines.append(f"sched add $DEMOS/memproc P{i} 24 local:600:24:6:{10 * rep + i + 1}:30 -c 50")
        lines.append("sched run rr -q 20 --quiet")
        out = run(lines)
        mp = memproc_lines(out)
        ss = sched_summary(out)
        if not ss or len(mp) != k:
            continue
        faults = sum(v[1] for v in mp.values())
        major = sum(v[3] for v in mp.values())
        vals.append((faults / k, major / k, ss[0], ss[1], ss[3]))
    if not vals:
        continue
    f, mj, mk, cpu, blocks = (st.mean(x[i] for x in vals) for i in range(5))
    M3.append((k, f, mj, mk, cpu, blocks))
table(["k", "faults/proc", "major/proc", "makespan ms", "CPU busy %", "blocks"],
      [[k, f"{f:.0f}", f"{mj:.0f}", f"{mk:.0f}", f"{cpu:.1f}", f"{b:.0f}"] for k, f, mj, mk, cpu, b in M3],
      [4, 13, 12, 13, 12, 9])
if len(M3) >= 2:
    k1, kn = M3[0], M3[-1]
    print(f"\n  1 process: {k1[1]:.0f} faults; {kn[0]} processes: {kn[1]:.0f} faults each "
          f"({kn[1] / max(1, k1[1]):.1f}x) - the working sets no longer fit in 16 frames")
    print(f"  throughput: {k1[3] / 1:.0f} ms for 1 process, {kn[3] / kn[0]:.0f} ms per process with {kn[0]}")

# ---------------------------------------------------------------------------
head("M4  The replacement policies on the live multiprogrammed workload (k = 4)")
rows = []
for pol in ("fifo", "lru", "clock"):
    vals = []
    for rep in range(REPS):
        lines = ["mem config -f 16 -s 256 -d 3", f"mem policy {pol}", "sched clear"]
        for i in range(4):
            lines.append(f"sched add $DEMOS/memproc P{i} 24 local:600:24:6:{10 * rep + i + 1}:30 -c 50")
        lines.append("sched run rr -q 20 --quiet")
        out = run(lines)
        mp = memproc_lines(out)
        ss = sched_summary(out)
        if ss and len(mp) == 4:
            vals.append((sum(v[1] for v in mp.values()), sum(v[3] for v in mp.values()), ss[0], ss[1]))
    if vals:
        rows.append([pol.upper() if pol != "clock" else "Clock"] + [f"{st.mean(v[i] for v in vals):.0f}" for i in range(3)] +
                    [f"{st.mean(v[3] for v in vals):.1f}"])
table(["policy", "faults", "major", "makespan ms", "CPU busy %"], rows, [8, 9, 8, 13, 12])

# ---------------------------------------------------------------------------
head("M5  Demand paging: memory given against memory used")
out = run(["mem config -f 16 -s 256 -d 0",
           "$DEMOS/memproc sparse 64 local:500:64:4:3:20 --hold 300 &", "sleep 0.15", "mem ps", "sleep 0.3",
           "$DEMOS/memproc dense 16 loop:16:5 -W --hold 300 &", "sleep 0.15", "mem ps", "sleep 0.3"])
rows = []
for ln in out.splitlines():
    t = ln.split()
    if len(t) > 13 and t[1] in ("sparse", "dense") and t[0].isdigit():
        rows.append([t[1], t[2], t[3], t[4], t[6], t[-3]])
table(["process", "allocated", "resident", "peak", "faults", "Linux RSS KB"], rows, [9, 11, 10, 6, 8, 14])
print("  pages that are allocated but never touched take no frame (demand paging); the real")
print("  Linux process that runs memproc has an RSS of its own code and libraries on top")

# ---------------------------------------------------------------------------
head("S1  The cost of mutual exclusion: 2 processes x 5000 increments of a shared counter")
rows = []
for mode, opt, cfg in (("none", "", "fifo"), ("mutex, FIFO hand-off", "--lock sm", "fifo"),
                       ("mutex, barging", "--lock sm", "barge"), ("semaphore, FIFO", "--sem ss", "fifo")):
    finals, times, waits = [], [], []
    for rep in range(REPS):
        out = run([f"sem config --handoff {cfg}", "$DEMOS/counter --reset sc",
                   f"$DEMOS/counter A 5000 --seg sc {opt} & $DEMOS/counter B 5000 --seg sc {opt} &",
                   "sleep 0.2", "sem", "sleep 4", "$DEMOS/counter --show sc", "sem"])
        m = re.search(r"counter in sc = (\d+)", out)
        t = [int(x) for x in re.findall(r"done, 5000 increments in (\d+) ms", out)]
        w = re.findall(r"^\s+s[ms]\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+(\d+)", out, re.M)
        if m and len(t) == 2:
            finals.append(int(m.group(1)))
            times.append(max(t))
            if w:
                waits.append(int(w[-1][1]))
    rows.append([mode, f"{st.mean(finals):.0f}", "yes" if all(f == 10000 for f in finals) else "NO",
                 f"{st.mean(times):.0f}", f"{st.mean(waits):.0f}" if waits else "-"])
table(["protection", "final value", "correct", "time ms", "sleeps"], rows, [22, 13, 9, 9, 8])
print("  (expected value 10000; 'sleeps' = lock requests that had to sleep)")

# ---------------------------------------------------------------------------
head("S2  Producer-consumer: 1 producer, 1 consumer, 2000 items, buffer size N")
rows = []
for n in (1, 2, 4, 8, 16, 64):
    vals = []
    for rep in range(REPS):
        out = run([f"$DEMOS/pc init {n}", "$DEMOS/pc producer 1 2000 & $DEMOS/pc consumer 1 2000 &", "sleep 6",
                   "$DEMOS/pc check pc.log 1 2000", "sem"])
        t = [int(x) for x in re.findall(r"done, 2000 items in (\d+) ms", out)]
        ok = "CORRECT" in out
        we = re.search(r"^\s+buf\.empty\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+(\d+)", out, re.M)
        wf = re.search(r"^\s+buf\.full\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+(\d+)", out, re.M)
        if len(t) == 2:
            vals.append((max(t), int(we.group(1)) if we else 0, int(wf.group(1)) if wf else 0, ok))
    if vals:
        rows.append([n, f"{st.mean(v[0] for v in vals):.0f}", f"{2000 * 1000 / st.mean(v[0] for v in vals):.0f}",
                     f"{st.mean(v[1] for v in vals):.0f}", f"{st.mean(v[2] for v in vals):.0f}",
                     "yes" if all(v[3] for v in vals) else "NO"])
table(["N", "time ms", "items/s", "P waits", "C waits", "correct"], rows, [5, 9, 9, 9, 9, 9])
print("  P waits = producer slept on 'empty' (buffer full); C waits = consumer slept on 'full'")

# ---------------------------------------------------------------------------
head("S3  Dining philosophers: 5 philosophers x 5 meals (think 10 ms, eat 10 ms)")
rows = []
for mode in ("ordered", "waiter", "naive"):
    vals = []
    for rep in range(REPS):
        extra = " --pause 50" if mode == "naive" else ""
        cmd = " & ".join(f"$DEMOS/philo {i} 5 5 --{mode} --think 10 --eat 10{extra}" for i in range(5)) + " &"
        out = run([cmd, "sleep 3", "sem deadlock", "jobs"])
        waits = [(int(a), int(b)) for a, b in re.findall(r"finished 5 meals; waited (\d+) ms in total for forks \(longest (\d+) ms\)", out)]
        dead = "DEADLOCK detected" in out
        vals.append((len(waits), st.mean(w[0] / 5 for w in waits) if waits else 0, max((w[1] for w in waits), default=0), dead))
    rows.append([mode, f"{st.mean(v[0] for v in vals):.1f}/5", f"{st.mean(v[1] for v in vals):.0f}",
                 f"{max(v[2] for v in vals)}", f"{sum(v[3] for v in vals)}/{REPS}"])
table(["strategy", "finished", "avg wait/meal ms", "max wait ms", "deadlocks"], rows, [10, 10, 18, 13, 11])
print("  naive = left fork, 50 ms pause, right fork: every run deadlocks and the shell names the cycle")
print("\nAll live figures above were measured on real processes using the shell's memory and semaphores.")
