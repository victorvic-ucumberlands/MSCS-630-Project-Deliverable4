# myshell - Deliverables 1-4: shell, process management, job control, CPU scheduling, memory, synchronization, pipes, security

C++17, Linux. Uses `fork`, `execvp`, `wait4`, `setpgid`, `tcsetpgrp`, `kill`, signals.

## Build & run
```
make                    # builds ./myshell  (g++ >= 7)
./myshell --setup-demo  # Deliverable 4: create the demo users and the managed file tree fs/ (resets them)
./myshell               # interactive shell: log in first (see "Security" below)
./myshell -u alice      # log in without the prompt, password from $MYSHELL_PASSWORD (for scripts)
./myshell script.msh    # run a script        (-e echoes each line first)
make demo               # run every demo + test, write evidence/*.log and evidence/SUMMARY.txt
make sanitize           # optional: ASan+UBSan build (./myshell_asan)
```

## Source layout
| file | purpose |
|------|---------|
| `src/main.cpp` | argument handling, picks interactive vs script mode |
| `src/shell.{hpp,cpp}` | read-eval loop, fork/exec/wait, foreground/background, job control, signals, cleanup |
| `src/parser.{hpp,cpp}` | lexer/parser: quotes, `$VAR $? $$ ~`, `; &`, `< > >> 2>`, validation |
| `src/builtins.{hpp,cpp}` | cd pwd exit echo clear ls cat mkdir rmdir rm touch kill + jobs fg bg help |
| `src/job.{hpp,cpp}` | `Job` record (PCB-lite) and `JobTable`; also the record of every simulated scheduler task |
| `src/cpu_sched.{hpp,cpp}` | **Deliverable 2** - the resident CPU scheduler every command goes through: FCFS / Round-Robin / Priority (binary heap), dispatch with SIGCONT, preemption with SIGSTOP confirmed by `wait4`, the quantum, block and wake-up detection from `/proc`, statistics |
| `src/scheduler.{hpp,cpp}` | **Deliverable 2** - `sched run` experiments on the same scheduler (other jobs parked), with a measured report and Gantt chart |
| `src/sched_builtin.cpp` | **Deliverable 2** - the `sched` built-in: live / policy / default / ps / trace, and add / list / remove / run / compare / stats |
| `demos/cpuburn.c` | CPU-bound helper used as a scheduler workload; reports how much CPU time it has consumed |
| `src/mkernel.h` | **Deliverable 3** - the "system call" interface between the shell and its processes (protocol + C client library + reference-string generators) |
| `src/kernel.{hpp,cpp}` | **Deliverable 3** - the server: Unix socket, one connection per process (SO_PEERCRED), deferred replies = blocking, scheduler hints, cleanup on exit |
| `src/memory.{hpp,cpp}` | **Deliverable 3** - paging: frames, page tables, demand paging, FIFO / LRU / Clock replacement, dirty bits, swap with one I/O device, shared segments; `mem sim` replay with OPT |
| `src/sync.{hpp,cpp}` | **Deliverable 3** - counting semaphores and owned (robust) mutexes, FIFO wait queues or barging, wait-for-graph deadlock detection |
| `src/mem_builtin.cpp` | **Deliverable 3** - the `mem` and `sem` built-ins |
| `src/crypto.{hpp,cpp}` | **Deliverable 4** - SHA-256, HMAC-SHA256, PBKDF2 (checked against Python's hashlib), random salts, constant-time compare |
| `src/security.{hpp,cpp}` | **Deliverable 4** - users, roles, authentication with lock-out, the permission model (owner/group/other rwx + sticky bit) and its checks, the audit log |
| `src/security_builtin.cpp` | **Deliverable 4** - login logout whoami id users useradd userdel usermod unlock passwd chmod chown access audit cp mv |
| `demos/memproc.c` `counter.c` `pc.c` `philo.c` `mktest.c` | **Deliverable 3** test programs: paging workload with data check, shared-counter race, producer-consumer, dining philosophers, API edge cases |

## The job record (`struct Job`, src/job.hpp)
Identity (`id`, `serial`, `pid`, `pgid`, `command`), state (`New/Ready/Running/Stopped/Done/Terminated`,
`exit_status`, `term_signal`, `stop_signal`), **scheduler fields** (`priority`, `queue_level`,
`burst_estimate_ms`, `remaining_ms`) and **accounting** (`arrival`, `first_run`, `finish`, `cpu_user_ms`,
`cpu_sys_ms`, `stop_count`, derived `turnaround_ms()/response_ms()/wait_ms()`).
Finished jobs move to `JobTable::history()`. `jobs -a` prints every record.

## Scheduling (Deliverable 2)

**Every command the shell starts is scheduled by the shell.** It is a real process created stopped; it waits in
a ready queue and only runs when the shell continues it with `SIGCONT`; the shell takes the CPU back with
`SIGSTOP`. One scheduled process runs at a time. Commands typed normally get the defaults:
**Round-Robin, 100 ms time slice, priority 10, block detection on.**

```
cpuburn A 300 100 &            # ordinary commands: scheduled with the defaults
cpuburn B 300 100 &
sched ps                       # one RUN, the other READY (stopped in the kernel: T)
sched trace on                 # print every scheduling decision as it happens
sched policy priority          # change the policy for everything (rr [-q MS] | priority [--no-preempt] | fcfs)
prio 1 cpuburn urgent 100 &    # one command with priority 1 (lower = more urgent): preempts at once
prio 2 %1                      # change a running job's priority
sched default 5                # priority for new commands
sched live off                 # let the kernel schedule the jobs instead (Deliverable 1 behaviour)
```
`kill`, `bg`, `fg`, Ctrl-C and Ctrl-Z go through the scheduler. The foreground job owns the terminal while it is
not stopped; while it waits in the ready queue the shell holds the terminal and applies Ctrl-C / Ctrl-Z itself.
A process that blocks (sleep, keyboard input, disk) gives the CPU away and rejoins the queue when it wakes.
`jobs -a` shows turnaround, waiting (time in the ready queue), response, CPU held, time blocked for every job.

Experiments: queue a workload with arrival times and priorities, run it under one policy, get a measured report.
The shell's other jobs are parked for the duration.
```
sched add demos/cpuburn A 300 100           # -p priority, -t arrival time (ms), -o output file
sched add -p 1 -t 300 demos/cpuburn B 100 50
sched run rr -q 100 -v                      # event log, kernel states, Gantt chart, per-process metrics
sched run priority [--no-preempt]
sched compare -q 25,100                     # the same workload under every policy
```
Options: `-c MS` context-switch cost, `-T MS` time budget, `-v` verbose, `--quiet`, `--no-block-detect`.

`tests/verify_schedule.py ./myshell ./demos/cpuburn` checks 30 scheduler properties on real runs, including
mutual exclusion sampled independently from `/proc`, for experiments and for ordinary commands.

## Memory management and synchronization (Deliverable 3)

The shell is the "kernel" for memory and semaphores. Every process it starts inherits `$MYSHELL_KERNEL`, the
address of the shell's socket; a process that connects gets a paged virtual address space, and every load/store
is a request the shell translates through the page table (like an MMU). A request the shell defers puts the
process to sleep (semaphore wait, page fault with swap I/O) and the scheduler marks it BLOCKED.
```
mem config -f 4 -p 4096 -s 16 -d 0    # 4 frames of 4 KB, 16 swap pages, swap I/O 0 ms per page
mem policy fifo|lru|clock             # page replacement (global)
demos/memproc A 8 7,0,1,2,0,3 -v      # 8 pages, then that reference string ('3w' = write); data checked
mem / mem frames / mem ps -a / mem pt %1 / mem trace on / mem stats
mem sim -a all -f 1-7 1,2,3,4,1,2,5,1,2,3,4,5      # offline table, FIFO/LRU/Clock/OPT, Belady's anomaly
demos/counter A 5000 & demos/counter B 5000 &      # race: lost updates (add --lock m for a mutex)
demos/pc init 8; demos/pc producer 1 400 & demos/pc consumer 1 400 &; demos/pc check pc.log 1 400
demos/philo 0 5 3 --naive|--ordered|--waiter ...   # dining philosophers (deadlock is detected)
sem / sem create NAME [N] / sem post NAME / sem trace on / sem deadlock / sem config --deadlock fail --handoff barge
```
Screenshot scripts for report figures 6-10: inside `./myshell`, run `source figures/fig06_race.msh` (also
`fig07_producer_consumer`, `fig08_pc_race_and_deadlock`, `fig09_dining_deadlock`, `fig10_dining_solutions`).

`tests/verify_memory.py ./myshell ./demos` checks 20 properties, including an independent Python implementation
of FIFO/LRU/Clock/OPT against both `mem sim` and live processes. `demos/24_memory_perf.py` runs experiments M1-M5, S1-S3.

## Pipes and security (Deliverable 4)
* **Pipes:** `a | b | c` (up to 16 stages; built-ins and programs may be mixed; `<` applies to the first stage,
  `>` to the last). A forked copy of the shell leads the pipeline's process group, so the scheduler, `jobs`, `kill`,
  `fg`/`bg` treat the whole pipeline as one job; its status is the last stage's.
* **Users** (created by `--setup-demo`): `admin`/`admin123` (role admin, `#` prompt), `alice`/`alice123` and
  `bob`/`bob12345` (standard), `guest`/`guest123` (read-only). Passwords are stored as PBKDF2-HMAC-SHA256
  with a random salt in `.myshell/passwd`; 5 failures lock an account; every login and denial goes to `.myshell/audit.log`.
* **Permissions:** inside `fs/` every file has an owner, a group and rwx bits for owner/group/others (plus the sticky
  bit); `ls -l`, `chmod`, `chown`, `access FILE` (shows each decision and the rule). The shell checks built-ins,
  redirections, the programs it runs (x) and their file arguments. System settings (`sched policy`, `mem config`, ...)
  and user management need admin; jobs and semaphores belong to the user who created them.
* `$MYSHELL_DIR`, `$MYSHELL_FS`, `$MYSHELL_HOME` are set by the shell for scripts.
* Screenshot scripts: `figures/d4/figNN_*.msh`, run inside myshell with `source $MYSHELL_DIR/figures/d4/...`
  (the first comment line says which user to log in as). The Deliverable 3 scripts `figures/fig06..10` need admin.

## Syntax
`cmd &` background, `a ; b` sequence, `a | b` pipes, `> >> < 2> 2>>` redirection, `'..'` `".."` `\x` quoting,
`$VAR ${VAR} $? $$ $! ~`, `# comment`. `&&` and `||` are rejected with a clear message.

## Demos (evidence)
`demos/01_builtins.msh` normal use of all built-ins - `02_process_mgmt.msh` fg/bg/stop/continue/kill, process
groups, ps evidence, job records - `03_errors.msh` invalid commands and inputs - `04_adversarial.msh` odd file names,
SIGTERM-ignoring job, stopped-job kill, deleted cwd, bg stdin - `05_nested_and_exit.msh` nested shell, exit guard,
cleanup - `06_limits.msh` (generated) line/arg limits, 100-job burst - `07_interactive_pty.py` real Ctrl-C / Ctrl-Z / fg / bg
through a pseudo-terminal. **Deliverable 2:** `15_live_sched.msh` (ordinary commands scheduled with defaults, trace, block
detection, `prio`, renice, job control through the scheduler, live off/on), `16_live_pty.py` (Ctrl-Z / Ctrl-C on a
queued foreground job, interactive `cat` beside a CPU hog), `08_roundrobin.msh`, `09_priority.msh`,
`10_sched_errors.msh`, `11_sched_limits.msh` (generated, 64 real processes), `12_sched_pty.py`, `13_performance.py`
(experiments E1-E7). **Deliverable 3:** `17_paging.msh`, `18_replacement.msh`, `19_mem_errors.msh`, `20_race.msh`,
`21_producer_consumer.msh`, `22_dining.msh`, `23_sync_errors.msh`, `24_memory_perf.py`, `tests/verify_memory.py`.
**Deliverable 4:** `26_pipes.msh`, `27_login_pty.py` (real terminal: login, wrong passwords, lock-out, useradd, passwd),
`28_permissions_alice.msh`, `29_permissions_bob.msh`, `30_permissions_guest.msh`, `31_admin.msh`,
`32_integration.msh`, `33_security_errors.msh` (a `# run-as: USER` line picks the user).
`run_demos.sh` runs everything and prints PASS/FAIL checks.

For screenshots: run `./myshell` yourself in a terminal and type the commands from the demo scripts
(or `./myshell -e demos/02_process_mgmt.msh` for a ready-made transcript).

## Known limitations (documented in the reports)
* No globbing / `&&` / `||`; `$?` of a pipeline is the last stage's only (no `PIPESTATUS`). `rm` has no `-r`.
* The permission model is enforced by the shell (a reference monitor in user space): all accounts share one
  real Unix uid, so a program that opens files by itself is not stopped by the kernel - only the files named on its
  command line are checked. Real separation would need one Unix uid per user (or Landlock / namespaces). A Deliverable 1 background job's finish time is stamped when the
  shell *reaps* it (at the next prompt), not at the instant it exits.
* Job control signals (Ctrl-C/Z) need a terminal; scripts use `kill -STOP/-CONT` instead.
* Blocking is detected by sampling `/proc` every 5 ms: a process that wakes up can run beside the dispatched one
  until the next probe (at most ~5 ms).
* Built-ins run inside the shell and are not scheduled; a background `sched run ... &` is a separate scheduler.
* Memory is simulated by the shell: only programs that use `src/mkernel.h` get paged memory (every access is a
  request, so it is slow - tens of microseconds); the shell's memory model is cooperative, not hardware-enforced.
