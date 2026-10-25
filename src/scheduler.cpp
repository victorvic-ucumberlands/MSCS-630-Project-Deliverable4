// scheduler.cpp - the `sched run` experiment harness, built on the resident
// CpuScheduler.  See scheduler.hpp.
#include "scheduler.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>

#include "kernel.hpp"

namespace {
long ms_of(const struct timeval& tv) { return tv.tv_sec * 1000L + tv.tv_usec / 1000L; }

// Fold a wait status into a process-control block.
void record_exit(SchedTask& t, int st, const struct rusage& ru) {
  t.pcb.cpu_user_ms = ms_of(ru.ru_utime);
  t.pcb.cpu_sys_ms = ms_of(ru.ru_stime);
  t.pcb.finish = Job::Clock::now();
  if (WIFEXITED(st)) {
    t.pcb.state = JobState::Done;
    t.pcb.exit_status = WEXITSTATUS(st);
  } else if (WIFSIGNALED(st)) {
    t.pcb.state = JobState::Terminated;
    t.pcb.term_signal = WTERMSIG(st);
  } else {
    t.pcb.state = JobState::Done;
    t.pcb.exit_status = -1;
  }
}

std::string how_it_ended(const SchedTask& t) {
  char buf[96];
  if (t.pcb.state == JobState::Terminated)
    snprintf(buf, sizeof buf, "killed by signal %d (%s)", t.pcb.term_signal, strsignal(t.pcb.term_signal));
  else
    snprintf(buf, sizeof buf, "exit status %d", t.pcb.exit_status);
  return std::string(buf) + ", cpu " + std::to_string(t.pcb.cpu_user_ms + t.pcb.cpu_sys_ms) + " ms";
}
}  // namespace

// ===========================================================================
// Workload management
// ===========================================================================
std::string Scheduler::add(const SchedTask& t) {
  if (tasks_.size() >= kMaxTasks) return "too many tasks (limit " + std::to_string(kMaxTasks) + ")";
  if (t.argv.empty()) return "no command given";
  tasks_.push_back(t);
  tasks_.back().pcb.id = next_id_;
  tasks_.back().pcb.serial = (unsigned long)next_id_;
  ++next_id_;
  return "";
}

bool Scheduler::remove(int id) {
  for (auto it = tasks_.begin(); it != tasks_.end(); ++it)
    if (it->pcb.id == id) { tasks_.erase(it); return true; }
  return false;
}

// ===========================================================================
// The experiment
// ===========================================================================
SchedResult Scheduler::run(const SchedConfig& cfg, FILE* out, CpuScheduler& cpu, Kernel* kern) {
  SchedResult r;
  r.cfg = cfg;
  r.tasks = tasks_;                       // fixed size from here on: the scheduler keeps pointers
  const size_t n = r.tasks.size();

  std::vector<size_t> order(n);           // arrival order, ties in submission order
  for (size_t i = 0; i < n; ++i) order[i] = i;
  std::stable_sort(order.begin(), order.end(),
                   [&](size_t a, size_t b) { return r.tasks[a].arrival_ms < r.tasks[b].arrival_ms; });
  size_t next_pending = 0;

  // ---- signals ------------------------------------------------------------
  // SIGCHLD (a task exited), SIGINT (Ctrl-C), and SIGTERM/SIGHUP (the run was
  // started with '&' and its job is being killed) are blocked for the run and
  // collected synchronously with sigtimedwait, so none can be lost and none
  // interrupts the bookkeeping.
  sigset_t watch, saved_mask;
  sigemptyset(&watch);
  for (int s : {SIGCHLD, SIGINT, SIGTERM, SIGHUP}) sigaddset(&watch, s);
  sigprocmask(SIG_BLOCK, &watch, &saved_mask);
  // With the system-call server the wait below is a poll() over its sockets
  // and a signalfd for the watched signals; without it, sigtimedwait().
  const int sigfd = kern ? signalfd(-1, &watch, SFD_NONBLOCK | SFD_CLOEXEC) : -1;

  // ---- take the CPU for the experiment ----------------------------------
  CpuConfig saved_cfg = cpu.config();
  auto saved_log = cpu.log;
  auto saved_before = cpu.before_continue, saved_after = cpu.after_stop;
  auto saved_collected = cpu.collected;
  auto saved_user = cpu.user_stopped;
  cpu.park_all();                          // the shell's other jobs wait until we are done
  cpu.configure(cfg.cpu());
  cpu.before_continue = nullptr;           // experiment tasks never own the terminal
  cpu.after_stop = nullptr;

  const long t0 = proc::mono_ms();
  auto rel = [&] { return proc::mono_ms() - t0; };
  cpu.record = true;
  cpu.reset_stats(t0);

  auto index_of = [&](const Job& pcb) -> int {
    for (size_t i = 0; i < n; ++i)
      if (&r.tasks[i].pcb == &pcb) return (int)i;
    return -1;
  };

  // ---- event log ---------------------------------------------------------
  auto ev = [&](const char* kind, const std::string& detail) {
    if (!cfg.trace) return;
    fprintf(out, "%7ld  %-8s %-44s ready=%s\n", rel(), kind, detail.c_str(), cpu.ready_text().c_str());
    if (cfg.verbose) {
      std::string line = "           tasks:";
      bool first = true;
      for (const SchedTask& t : r.tasks) {
        line += (first ? " " : ", ") + t.pcb.command + "=";
        first = false;
        if (!t.spawned) { line += "unborn(@" + std::to_string(t.arrival_ms) + "ms)"; continue; }
        const CpuEntry* e = cpu.entry_of(t.pcb);
        std::string st = e ? to_string(e->state) : (t.pcb.finished() ? "GONE" : "?");
        line += st + "[kernel " + std::string(1, proc::state(t.pcb.finished() ? 0 : t.pcb.pid)) +
                ",pid " + std::to_string((int)t.pcb.pid) + ",cpu-held " +
                std::to_string(t.pcb.dispatched_ms) + "ms]";
      }
      fprintf(out, "%s\n", line.c_str());
      if (!strcmp(kind, "DISPATCH"))
        fprintf(out, "           why: %s\n",
                cfg.policy == PolicyKind::Priority
                    ? "lowest priority number in the heap; equal priorities go to the earliest arrival"
                    : "front of the FIFO ready queue (the task that has waited longest)");
    }
    fflush(out);
  };
  cpu.log = ev;

  // The engine itself may collect a task's exit (it exited at the instant it
  // was being stopped); record it here.  Must not call back into the engine.
  cpu.collected = [&](Job& pcb, int st, const struct rusage& ru) {
    int i = index_of(pcb);
    if (i < 0) return;
    record_exit(r.tasks[i], st, ru);
    ev("FINISH", pcb.command + ": " + how_it_ended(r.tasks[i]) + " (exited as it was stopped)");
  };
  // A task stopped by somebody else is put back in the queue after the tick.
  std::vector<Job*> readmit;
  cpu.user_stopped = [&](Job& pcb, int) { readmit.push_back(&pcb); };

  // ---- process creation --------------------------------------------------
  // The child joins a new process group, restores normal signal handling,
  // reads /dev/null (a stopped process must never hold the terminal), and
  // STOPS ITSELF before exec: when spawn() returns the task exists as a real
  // process in the ready queue and has not run a single instruction of the
  // user's program.  The cost of exec is paid inside its first time slice.
  enum class Spawn { Ready, DiedEarly, Failed };
  auto spawn = [&](SchedTask& t) -> Spawn {
    fflush(out);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
      fprintf(stderr, "sched: fork failed: %s\n", strerror(errno));
      return Spawn::Failed;
    }
    if (pid == 0) {                                     // ---- child ----
      setpgid(0, 0);
      sigset_t none;
      sigemptyset(&none);
      sigprocmask(SIG_SETMASK, &none, nullptr);
      for (int s : {SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGCHLD, SIGPIPE, SIGTERM, SIGHUP})
        signal(s, SIG_DFL);
      prctl(PR_SET_PDEATHSIG, SIGKILL);                 // never outlive the shell while stopped
      int nul = open("/dev/null", O_RDONLY);
      if (nul >= 0) { dup2(nul, STDIN_FILENO); close(nul); }
      if (!t.out_path.empty()) {
        int fd = open(t.out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
          fprintf(stderr, "sched: %s: %s\n", t.out_path.c_str(), strerror(errno));
          _exit(126);
        }
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
      }
      raise(SIGSTOP);                                   // <-- born Ready, not Running
      std::vector<char*> av;
      for (auto& a : t.argv) av.push_back(const_cast<char*>(a.c_str()));
      av.push_back(nullptr);
      execvp(av[0], av.data());
      int e = errno;
      if (e == ENOENT && t.argv[0].find('/') == std::string::npos)
        fprintf(stderr, "sched: %s: command not found\n", av[0]);
      else
        fprintf(stderr, "sched: %s: %s\n", av[0], strerror(e));
      _exit(e == ENOENT ? 127 : 126);
    }
    setpgid(pid, pid);                                  // ---- parent ----
    t.pcb.pid = t.pcb.pgid = pid;
    t.pcb.scheduled = true;
    t.spawned = true;
    int st = 0;
    struct rusage ru{};
    pid_t got;
    while ((got = wait4(pid, &st, WUNTRACED, &ru)) < 0 && errno == EINTR) {}
    if (got > 0 && !WIFSTOPPED(st)) {
      // It died before reaching its SIGSTOP (e.g. -o FILE could not be
      // opened), so it never entered the ready queue.  Queueing it anyway
      // would make the scheduler wait forever for a process that is gone.
      t.pcb.first_run = t.pcb.arrival;
      record_exit(t, st, ru);
      return Spawn::DiedEarly;
    }
    t.pcb.state = JobState::Running;                    // alive (the CPU state is the engine's)
    return Spawn::Ready;
  };

  // Collect state changes of our own tasks only (never wait4(-1): the shell's
  // other jobs are parked and their statuses must stay for the shell).
  auto reap = [&]() {
    for (SchedTask& t : r.tasks) {
      if (!t.spawned || t.pcb.finished()) continue;
      int st = 0;
      struct rusage ru{};
      pid_t got = wait4(t.pcb.pid, &st, WNOHANG | WUNTRACED, &ru);
      if (got == 0) continue;
      if (got < 0) {
        if (errno == EINTR) continue;
        cpu.forget(t.pcb);
        t.pcb.state = JobState::Done;
        t.pcb.exit_status = -1;
        t.pcb.finish = Job::Clock::now();
        ev("FINISH", t.pcb.command + ": disappeared (already reaped)");
        continue;
      }
      if (WIFSTOPPED(st)) {             // it stopped itself: back to the ready queue
        cpu.forget(t.pcb);
        cpu.admit(t.pcb, (int)(&t - r.tasks.data()), t.arrival_ms, t.pcb.serial);
        ev("YIELD", t.pcb.command + ": suspended itself, back in the ready queue");
        continue;
      }
      record_exit(t, st, ru);
      cpu.exited(t.pcb);
      ev("FINISH", t.pcb.command + ": " + how_it_ended(t));
    }
  };

  auto all_done = [&]() {
    if (next_pending < n) return false;
    for (const SchedTask& t : r.tasks)
      if (t.spawned && !t.pcb.finished()) return false;
    return true;
  };

  // ---- main loop: admit arrivals, let the scheduler decide, wait ---------
  bool idle_logged = false;
  while (true) {
    long now = rel();

    // 1. Create every task whose arrival time has come.
    while (next_pending < n && r.tasks[order[next_pending]].arrival_ms <= now) {
      size_t i = order[next_pending++];
      SchedTask& t = r.tasks[i];
      t.pcb.arrival = Job::Clock::now();
      Spawn sp = spawn(t);
      if (sp == Spawn::Failed) {
        t.pcb.state = JobState::Done;
        t.pcb.exit_status = 126;
        t.pcb.first_run = t.pcb.finish = t.pcb.arrival;
        continue;
      }
      if (sp == Spawn::DiedEarly) {
        ev("FINISH", t.pcb.command + ": could not start, exit status " +
                         std::to_string(t.pcb.exit_status) + " (never queued)");
        continue;
      }
      cpu.admit(t.pcb, (int)i, t.arrival_ms, t.pcb.serial);
      ev("ARRIVE", t.pcb.command + ": created (pid " + std::to_string((int)t.pcb.pid) + ", prio " +
                       std::to_string(t.pcb.priority) + "), stopped in ready queue");
    }

    // 2. Let the scheduler make every decision that is due now.
    cpu.tick();
    for (Job* p : readmit) cpu.admit(*p, index_of(*p), r.tasks[index_of(*p)].arrival_ms, p->serial);
    if (!readmit.empty()) { readmit.clear(); cpu.tick(); }

    if (all_done()) break;
    if (rel() > cfg.budget_ms) { r.over_budget = true; break; }

    if (cpu.running()) idle_logged = false;
    if (!cpu.running() && !cpu.has_ready() && !cpu.has_blocked() && next_pending < n && !idle_logged) {
      ev("IDLE", "no task ready; waiting for the arrival at " +
                     std::to_string(r.tasks[order[next_pending]].arrival_ms) + " ms");
      idle_logged = true;
    }

    // 3. Sleep until the next thing that can change a decision: the time
    //    slice, a probe for blocking, the next arrival, or the budget - or
    //    until a signal arrives.  This wait IS the quantum timer.
    long t = cpu.timeout_ms();
    auto take = [&](long v) { if (v < 0) v = 0; if (t < 0 || v < t) t = v; };
    if (next_pending < n) take(r.tasks[order[next_pending]].arrival_ms - rel());
    take(cfg.budget_ms - rel() + 1);
    if (sigfd >= 0) {
      if (long kt = kern->timeout_ms(); kt >= 0) take(kt);
      std::vector<pollfd> fds{{sigfd, POLLIN, 0}};
      kern->add_pollfds(fds);
      poll(fds.data(), fds.size(), (int)std::min<long>(t, 1000000));
      kern->service(fds.data() + 1, fds.size() - 1);
      kern->tick();
      int stop_sig = 0;
      signalfd_siginfo si;
      bool chld = false;
      while (read(sigfd, &si, sizeof si) == (ssize_t)sizeof si) {
        if (si.ssi_signo == SIGCHLD) chld = true;
        else stop_sig = (int)si.ssi_signo;
      }
      if (chld) reap();
      if (stop_sig) {
        r.interrupted = true;
        r.abort_signal = stop_sig;
        break;
      }
      continue;
    }
    timespec ts{t / 1000, (t % 1000) * 1000000L};
    siginfo_t info;
    int s = sigtimedwait(&watch, &info, &ts);
    if (s == SIGCHLD) {
      reap();
    } else if (s == SIGINT || s == SIGTERM || s == SIGHUP) {
      r.interrupted = true;
      r.abort_signal = s;
      break;
    }
  }
  if (sigfd >= 0) close(sigfd);
  r.makespan_ms = rel();

  // ---- cleanup: never leave a stopped child behind -----------------------
  for (SchedTask& t : r.tasks) {
    if (!t.spawned || t.pcb.finished()) continue;
    t.aborted = true;
    cpu.forget(t.pcb);
    kill(-t.pcb.pgid, SIGCONT);                         // a stopped process cannot act on SIGTERM
    kill(-t.pcb.pgid, SIGTERM);
    bool gone = false;
    for (int i = 0; i < 200 && !gone; ++i) {
      int st = 0;
      struct rusage ru{};
      pid_t got = wait4(t.pcb.pid, &st, WNOHANG, &ru);
      if (got > 0) { record_exit(t, st, ru); gone = true; }
      else if (got < 0) gone = true;
      else proc::sleep_ms(1);
    }
    if (!gone) {
      kill(-t.pcb.pgid, SIGKILL);
      int st = 0;
      struct rusage ru{};
      while (wait4(t.pcb.pid, &st, 0, &ru) < 0 && errno == EINTR) {}
      record_exit(t, st, ru);
    }
  }

  // ---- results and restoration -------------------------------------------
  r.gantt = cpu.stats.gantt;
  r.gantt_truncated = cpu.stats.gantt_truncated;
  r.busy_ms = cpu.stats.busy_ms;
  r.idle_ms = cpu.stats.idle_ms;
  r.overhead_ms = cpu.stats.overhead_ms;
  r.context_switches = cpu.stats.context_switches;
  r.preemptions = cpu.stats.preemptions;
  r.blocks = cpu.stats.blocks;

  cpu.record = false;
  cpu.log = saved_log;
  cpu.collected = saved_collected;
  cpu.user_stopped = saved_user;
  cpu.configure(saved_cfg);
  cpu.before_continue = saved_before;
  cpu.after_stop = saved_after;
  cpu.unpark_all();                                     // the shell's jobs carry on

  // Drop SIGCHLDs from our own (now reaped) children so the shell is not
  // woken for them; any other pending signal stays pending for the shell.
  {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    timespec zero{0, 0};
    while (sigtimedwait(&chld, nullptr, &zero) > 0) {}
  }
  sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
  return r;
}

// ===========================================================================
// Metrics
// ===========================================================================
int SchedResult::finished_count() const {
  int c = 0;
  for (const SchedTask& t : tasks)
    if (t.pcb.finished() && !t.aborted) ++c;
  return c;
}
static double mean_over_completed(const SchedResult& r, long (Job::*f)() const) {
  double sum = 0;
  int c = 0;
  for (const SchedTask& t : r.tasks)
    if (t.pcb.finished() && !t.aborted) { sum += (double)(t.pcb.*f)(); ++c; }
  return c ? sum / c : 0.0;
}
double SchedResult::avg_waiting_ms() const { return mean_over_completed(*this, &Job::wait_ms); }
double SchedResult::avg_turnaround_ms() const { return mean_over_completed(*this, &Job::turnaround_ms); }
double SchedResult::avg_response_ms() const { return mean_over_completed(*this, &Job::response_ms); }
double SchedResult::cpu_utilization() const { return makespan_ms ? 100.0 * busy_ms / makespan_ms : 0.0; }
double SchedResult::throughput_per_s() const {
  return makespan_ms ? 1000.0 * finished_count() / makespan_ms : 0.0;
}

// ===========================================================================
// Reporting
// ===========================================================================
static void print_gantt(const SchedResult& r, FILE* out) {
  fprintf(out, "Gantt chart (ms of real time):\n");
  if (r.gantt.empty()) { fprintf(out, "  (nothing ran)\n"); return; }
  if (r.gantt.size() > 30) {
    fprintf(out, "  %zu segments%s - chart omitted (use a larger time slice to see it)\n",
            r.gantt.size(), r.gantt_truncated ? ", truncated" : "");
    return;
  }
  const long total = std::max(1L, r.gantt.back().end);
  std::string bar = "  |", axis = "  ";
  for (const auto& g : r.gantt) {
    std::string label = g.kind == GanttSegment::Task && g.tag >= 0 && (size_t)g.tag < r.tasks.size()
                            ? r.tasks[g.tag].pcb.command
                            : g.kind == GanttSegment::Idle ? "idle" : "cs";
    if (label.size() > 10) label = label.substr(0, 10);
    std::string t = std::to_string(g.start);
    size_t w = std::max({label.size() + 1, t.size() + 1,
                         (size_t)std::lround(56.0 * (g.end - g.start) / total)});
    bar += label + std::string(w - label.size(), ' ') + "|";
    axis += t + std::string(w + 1 - t.size(), ' ');
  }
  axis += std::to_string(r.gantt.back().end);
  fprintf(out, "%s\n%s\n", bar.c_str(), axis.c_str());
}

void Scheduler::print_report(const SchedResult& r, FILE* out) {
  fprintf(out, "\n=== %s ===\n", describe(r.cfg).c_str());
  if (r.interrupted) {
    const char* sig = r.abort_signal == SIGINT ? "SIGINT (Ctrl-C)"
                    : r.abort_signal == SIGTERM ? "SIGTERM (the job was killed)"
                    : r.abort_signal == SIGHUP ? "SIGHUP" : "a signal";
    fprintf(out, "!!! run cut short by %s: unfinished tasks were terminated and are excluded from the averages\n", sig);
  }
  if (r.over_budget) fprintf(out, "!!! time budget of %ld ms exceeded: unfinished tasks were terminated\n", r.cfg.budget_ms);
  print_gantt(r, out);

  size_t nw = 7;
  for (const SchedTask& t : r.tasks) nw = std::max(nw, t.pcb.command.size());
  if (nw > 28) nw = 28;

  fprintf(out, "\nPer-process metrics (ms of real time, measured):\n");
  fprintf(out, "  %-3s %-*s %5s %7s %7s %7s %7s %7s %7s %7s %6s %6s %s\n", "ID", (int)nw, "COMMAND",
          "PRIO", "ARRIVE", "START", "FINISH", "WAIT", "BLOCK", "TURN", "RESP", "CPU", "SLICES", "RESULT");
  for (const SchedTask& t : r.tasks) {
    std::string cmd = t.pcb.command.size() > nw ? t.pcb.command.substr(0, nw - 1) + "~" : t.pcb.command;
    char result[40];
    if (t.aborted) snprintf(result, sizeof result, "terminated (unfinished)");
    else if (t.pcb.state == JobState::Terminated) snprintf(result, sizeof result, "signal %d", t.pcb.term_signal);
    else if (t.pcb.state == JobState::Done) snprintf(result, sizeof result, "exit %d", t.pcb.exit_status);
    else snprintf(result, sizeof result, "%s", to_string(t.pcb.state));

    if (t.pcb.finished() && !t.aborted) {
      fprintf(out, "  %-3d %-*s %5d %7ld %7ld %7ld %7ld %7ld %7ld %7ld %6ld %6d %s\n", t.pcb.id, (int)nw,
              cmd.c_str(), t.pcb.priority, t.arrival_ms, t.arrival_ms + t.pcb.response_ms(),
              t.arrival_ms + t.pcb.turnaround_ms(), t.pcb.wait_ms(), t.pcb.blocked_ms,
              t.pcb.turnaround_ms(), t.pcb.response_ms(), t.pcb.cpu_user_ms + t.pcb.cpu_sys_ms,
              t.pcb.dispatches, result);
    } else {
      fprintf(out, "  %-3d %-*s %5d %7ld %7s %7s %7s %7s %7s %7s %6ld %6d %s\n", t.pcb.id, (int)nw,
              cmd.c_str(), t.pcb.priority, t.arrival_ms, "-", "-", "-", "-", "-", "-",
              t.pcb.cpu_user_ms + t.pcb.cpu_sys_ms, t.pcb.dispatches, result);
    }
  }
  fprintf(out, "\n  arrive/start/finish are ms after the start of the run;  turnaround = finish - arrival;\n");
  fprintf(out, "  response = first dispatch - arrival;  wait = time in the ready queue;  block = time blocked\n");
  fprintf(out, "  in the kernel (sleep, I/O);  CPU = user+system time charged by the kernel (wait4 rusage).\n");

  fprintf(out, "\nAverages over %d completed task(s):  waiting %.1f ms   turnaround %.1f ms   response %.1f ms\n",
          r.finished_count(), r.avg_waiting_ms(), r.avg_turnaround_ms(), r.avg_response_ms());
  fprintf(out, "System:     makespan %ld ms   CPU busy %ld ms (%.1f%%)   throughput %.2f tasks/s\n",
          r.makespan_ms, r.busy_ms, r.cpu_utilization(), r.throughput_per_s());
  fprintf(out, "Switching:  %d context switches   %d preemptions (SIGSTOP)   %ld ms switch overhead   %ld ms idle   %d blocks\n",
          r.context_switches, r.preemptions, r.overhead_ms, r.idle_ms, r.blocks);
}
