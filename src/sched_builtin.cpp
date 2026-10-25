// sched_builtin.cpp - the `sched` built-in: user interface of the scheduler.
//
// Everyday scheduling (every command the shell starts):
//   sched live [on|off]                       is the shell scheduling its commands?
//   sched policy [rr [-q MS] | priority [--no-preempt] | fcfs] [-c MS] [--no-block-detect]
//   sched default [N]                         priority given to commands (default 10)
//   sched ps                                  what the scheduler is doing right now
//   sched trace [on|off]                      print scheduling decisions as they happen
//   prio N COMMAND...  /  prio N %JOB         (built into the shell: shell.cpp)
//
// Experiments (a queued workload executed under one policy, with a report):
//   sched add [-p N] [-t MS] [-o FILE] COMMAND [ARGS...]
//   sched list | remove ID | clear
//   sched run rr|priority|fcfs [options]
//   sched compare [-q q1,q2,...] [options]
//   sched stats
#include <signal.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "builtins.hpp"
#include "shell.hpp"

using Args = std::vector<std::string>;

namespace {

// Strict decimal parser: digits only, inside [lo, hi].
bool parse_num(const std::string& s, long& out, long lo, long hi) {
  if (s.empty() || s.size() > 9) return false;
  for (char c : s)
    if (c < '0' || c > '9') return false;
  long v = std::strtol(s.c_str(), nullptr, 10);
  if (v < lo || v > hi) return false;
  out = v;
  return true;
}

void usage() {
  puts("sched - the shell's CPU scheduler.  Every command the shell starts is a real process that\n"
       "the shell schedules itself: it is created stopped, waits in a ready queue, and is given the\n"
       "CPU with SIGCONT and preempted with SIGSTOP.  Only one scheduled process runs at a time.\n"
       "\n"
       "Everyday scheduling\n"
       "  sched live [on|off]                show or switch scheduling of ordinary commands\n"
       "  sched policy [POLICY] [-c MS] [--no-block-detect]   show or change the policy:\n"
       "        rr [-q MS]            Round-Robin, time slice MS (default 100)\n"
       "        priority [--no-preempt]   heap ordered by priority, ties first-come-first-served\n"
       "        fcfs                  first come, first served\n"
       "  sched default [N]                  priority given to new commands (0-99, lower = more urgent)\n"
       "  prio N COMMAND [ARGS...]           run one command with priority N (works with &)\n"
       "  prio N %JOB                        change the priority of a running job\n"
       "  sched ps                           every scheduled job and its CPU state right now\n"
       "  sched trace [on|off]               print each scheduling decision as it happens\n"
       "\n"
       "Experiments (a queued workload run under one policy, with a measured report)\n"
       "  sched add [-p N] [-t MS] [-o FILE] COMMAND [ARGS...]\n"
       "        -p priority (default 10), -t arrival time in ms after the run starts, -o output file\n"
       "  sched list | sched remove ID | sched clear\n"
       "  sched run rr [-q MS] | priority [--no-preempt] | fcfs\n"
       "        options: -c MS switch cost, -T MS time budget, -v verbose (incl. kernel state),\n"
       "                 --quiet no event log, --no-block-detect keep a blocked task on the CPU\n"
       "  sched compare [-q q1,q2,...] [options]   replay the workload under every policy\n"
       "  sched stats                        print the report of the last run again\n"
       "\n"
       "  Ctrl-C interrupts a run; unfinished processes are terminated, never left stopped.");
}

int fail(const char* sub, const std::string& msg) {
  fprintf(stderr, "sched %s: %s\n", sub, msg.c_str());
  return 1;
}

// Parse "rr [-q MS] | priority [--no-preempt] | fcfs" plus the common options
// into `c`.  Returns "" or an error message.
std::string parse_policy(const Args& a, size_t from, CpuConfig& c) {
  if (from >= a.size()) return "missing policy (rr, priority or fcfs)";
  const std::string& p = a[from];
  if (p == "rr" || p == "roundrobin" || p == "round-robin") c.policy = PolicyKind::RoundRobin;
  else if (p == "priority" || p == "prio") c.policy = PolicyKind::Priority;
  else if (p == "fcfs" || p == "fifo") c.policy = PolicyKind::FCFS;
  else return "unknown policy '" + p + "' (use rr, priority or fcfs)";
  bool q_given = false, np_given = false;
  for (size_t i = from + 1; i < a.size(); ++i) {
    long v;
    if (a[i] == "-q" || a[i] == "-c") {
      if (i + 1 >= a.size()) return "option " + a[i] + " needs a value in ms";
      if (a[i] == "-q") {
        if (!parse_num(a[i + 1], v, 1, 600000))
          return "time slice must be an integer from 1 to 600000 ms, got '" + a[i + 1] + "'";
        c.quantum_ms = v;
        q_given = true;
      } else {
        if (!parse_num(a[i + 1], v, 0, 10000))
          return "context-switch cost must be an integer from 0 to 10000 ms, got '" + a[i + 1] + "'";
        c.switch_cost_ms = v;
      }
      ++i;
    } else if (a[i] == "--no-preempt") {
      c.preemptive = false;
      np_given = true;
    } else if (a[i] == "--no-block-detect") {
      c.block_detect = false;
    } else if (a[i] == "--block-detect") {
      c.block_detect = true;
    } else {
      return "unknown option '" + a[i] + "'";
    }
  }
  if (q_given && c.policy != PolicyKind::RoundRobin) return "-q (time slice) only applies to rr";
  if (np_given && c.policy != PolicyKind::Priority) return "--no-preempt only applies to priority";
  return "";
}

// ===========================================================================
// Everyday scheduling
// ===========================================================================
void print_live_status(Shell& sh) {
  if (sh.live)
    printf("live scheduling ON: %s; default priority %d\n", describe(sh.cpu.config()).c_str(),
           sh.default_priority);
  else
    printf("live scheduling OFF: the kernel schedules the shell's jobs (policy kept: %s; default priority %d)\n",
           describe(sh.cpu.config()).c_str(), sh.default_priority);
}

int cmd_live(Shell& sh, const Args& a) {
  if (a.size() == 2) { print_live_status(sh); return 0; }
  if (a.size() != 3 || (a[2] != "on" && a[2] != "off")) return fail("live", "usage: sched live [on|off]");
  sh.set_live(a[2] == "on");
  print_live_status(sh);
  return 0;
}

int cmd_policy(Shell& sh, const Args& a) {
  if (a.size() == 2) { print_live_status(sh); return 0; }
  CpuConfig c;                                       // unspecified options take their defaults
  std::string err = parse_policy(a, 2, c);
  if (!err.empty()) return fail("policy", err);
  sh.cpu.configure(c);                               // the ready queue is rebuilt under it
  sh.schedule_tick();
  print_live_status(sh);
  return 0;
}

int cmd_default(Shell& sh, const Args& a) {
  size_t i = 2;
  if (i < a.size() && a[i] == "-p") ++i;
  if (i >= a.size()) { printf("default priority %d\n", sh.default_priority); return 0; }
  long v;
  if (i + 1 != a.size() || !parse_num(a[i], v, 0, 99))
    return fail("default", "priority must be an integer from 0 to 99, got '" + a[i] + "'");
  sh.default_priority = (int)v;
  printf("default priority %d (applies to commands started from now on)\n", sh.default_priority);
  return 0;
}

int cmd_trace(Shell& sh, const Args& a) {
  if (a.size() == 2) { printf("scheduling trace %s\n", sh.live_trace ? "on" : "off"); return 0; }
  if (a.size() != 3 || (a[2] != "on" && a[2] != "off")) return fail("trace", "usage: sched trace [on|off]");
  sh.live_trace = (a[2] == "on");
  printf("scheduling trace %s\n", sh.live_trace ? "on (events go to stderr)" : "off");
  return 0;
}

int cmd_ps(Shell& sh) {
  sh.reap_children(false);
  print_live_status(sh);
  long now = proc::mono_ms();
  auto act = sh.jobs.active();
  if (act.empty()) { puts("(no jobs)"); return 0; }
  printf("  %-5s %-7s %4s  %-9s %6s %9s %9s %9s %6s  %s\n", "JOB", "PID", "PRIO", "CPU-STATE", "KERNEL",
         "HELD(ms)", "WAIT(ms)", "BLOCK(ms)", "SLICES", "COMMAND");
  for (Job* j : act) {
    if (j->finished()) continue;
    const CpuEntry* e = sh.cpu.entry_of(*j);
    long held = j->dispatched_ms, wait = j->ready_ms, block = j->blocked_ms;
    std::string st;
    if (e) {
      st = to_string(e->state);
      long d = now - e->since_ms;
      if (e->state == CpuEntry::State::Running) held += d;
      else if (e->state == CpuEntry::State::Blocked) block += d;
      else wait += d;
    } else if (j->state == JobState::Stopped) {
      st = "STOPPED";                                // stopped by the user: not scheduled
    } else {
      st = "KERNEL";                                 // live scheduling off
    }
    char job[16];
    snprintf(job, sizeof job, "[%d]", j->id);
    std::string why = sh.kern.wait_reason(j->pid);     // Deliverable 3: asleep in a system call
    printf("  %-5s %-7d %4d  %-9s %6c %9ld %9ld %9ld %6d  %s%s\n", job, (int)j->pid, j->priority, st.c_str(),
           proc::state(j->pid), held, wait, block, j->dispatches, j->command.c_str(),
           why.empty() ? "" : ("   <- waits for " + why).c_str());
  }
  if (sh.live) printf("ready queue (service order): %s\n", sh.cpu.ready_text().c_str());
  return 0;
}

// ===========================================================================
// Experiments
// ===========================================================================
int cmd_add(Shell& sh, const Args& a) {
  SchedTask t;
  t.pcb.priority = 10;
  size_t i = 2;
  for (; i < a.size(); ++i) {
    if (a[i] == "--") { ++i; break; }
    if (a[i].size() < 2 || a[i][0] != '-') break;      // start of the command
    long v;
    if (a[i] == "-p" || a[i] == "-t" || a[i] == "-o") {
      if (i + 1 >= a.size()) return fail("add", "option " + a[i] + " needs a value");
      const std::string& val = a[i + 1];
      if (a[i] == "-p") {
        if (!parse_num(val, v, 0, 99)) return fail("add", "priority must be an integer from 0 to 99, got '" + val + "'");
        t.pcb.priority = (int)v;
      } else if (a[i] == "-t") {
        if (!parse_num(val, v, 0, Scheduler::kMaxArrivalMs))
          return fail("add", "arrival time must be an integer from 0 to " +
                                 std::to_string(Scheduler::kMaxArrivalMs) + " ms, got '" + val + "'");
        t.arrival_ms = v;
      } else {
        if (val.empty()) return fail("add", "-o needs a file name");
        t.out_path = val;
      }
      ++i;
    } else {
      return fail("add", "unknown option '" + a[i] + "' (expected -p, -t or -o)");
    }
  }
  if (i >= a.size()) return fail("add", "usage: sched add [-p N] [-t MS] [-o FILE] COMMAND [ARGS...]");
  for (; i < a.size(); ++i) t.argv.push_back(a[i]);
  t.pcb.command = short_label(t.argv);

  std::string err = sh.scheduler.add(t);
  if (!err.empty()) return fail("add", err);
  const SchedTask& added = sh.scheduler.workload().back();
  printf("queued [%d] %s   priority %d, arrives at %ld ms\n", added.pcb.id, added.pcb.command.c_str(),
         added.pcb.priority, added.arrival_ms);
  return 0;
}

int cmd_list(Shell& sh) {
  const auto& w = sh.scheduler.workload();
  if (w.empty()) { puts("the experiment queue is empty (use 'sched add COMMAND')"); return 0; }
  printf("  %-3s %5s %8s %-16s %s\n", "ID", "PRIO", "ARRIVAL", "LABEL", "COMMAND");
  for (const auto& t : w) {
    std::string full;
    for (size_t k = 0; k < t.argv.size(); ++k) full += (k ? " " : "") + t.argv[k];
    if (!t.out_path.empty()) full += "  > " + t.out_path;
    printf("  %-3d %5d %8ld %-16s %s\n", t.pcb.id, t.pcb.priority, t.arrival_ms, t.pcb.command.c_str(), full.c_str());
  }
  printf("%zu task(s) queued\n", w.size());
  return 0;
}

// Options of `run` and `compare` after the policy.
std::string parse_run_options(const Args& a, size_t from, SchedConfig& cfg, bool& q_given, bool& np_given) {
  for (size_t i = from; i < a.size(); ++i) {
    long v;
    if (a[i] == "-q" || a[i] == "-c" || a[i] == "-T") {
      if (i + 1 >= a.size()) return "option " + a[i] + " needs a value in ms";
      const std::string& val = a[i + 1];
      if (a[i] == "-q") {
        if (!parse_num(val, v, 1, 600000)) return "time slice must be an integer from 1 to 600000 ms, got '" + val + "'";
        cfg.quantum_ms = v;
        q_given = true;
      } else if (a[i] == "-c") {
        if (!parse_num(val, v, 0, 10000)) return "context-switch cost must be an integer from 0 to 10000 ms, got '" + val + "'";
        cfg.switch_cost_ms = v;
      } else {
        if (!parse_num(val, v, 100, Scheduler::kMaxBudgetMs))
          return "time budget must be an integer from 100 to " + std::to_string(Scheduler::kMaxBudgetMs) +
                 " ms, got '" + val + "'";
        cfg.budget_ms = v;
      }
      ++i;
    } else if (a[i] == "-v" || a[i] == "--verbose") {
      cfg.verbose = true;
    } else if (a[i] == "--quiet") {
      cfg.trace = false;
    } else if (a[i] == "--no-preempt") {
      cfg.preemptive = false;
      np_given = true;
    } else if (a[i] == "--no-block-detect") {
      cfg.block_detect = false;
    } else {
      return "unknown option '" + a[i] + "'";
    }
  }
  return "";
}

int cmd_run(Shell& sh, const Args& a) {
  if (a.size() < 3)
    return fail("run", "usage: sched run rr|priority|fcfs [-q MS] [-c MS] [-T MS] [-v] [--quiet]");
  SchedConfig cfg;
  const std::string& p = a[2];
  if (p == "rr" || p == "roundrobin" || p == "round-robin") cfg.policy = PolicyKind::RoundRobin;
  else if (p == "priority" || p == "prio") cfg.policy = PolicyKind::Priority;
  else if (p == "fcfs" || p == "fifo") cfg.policy = PolicyKind::FCFS;
  else return fail("run", "unknown policy '" + p + "' (use rr, priority or fcfs)");

  bool q_given = false, np_given = false;
  std::string err = parse_run_options(a, 3, cfg, q_given, np_given);
  if (!err.empty()) return fail("run", err);
  if (q_given && cfg.policy != PolicyKind::RoundRobin) return fail("run", "-q (time slice) only applies to rr");
  if (np_given && cfg.policy != PolicyKind::Priority) return fail("run", "--no-preempt only applies to priority");
  if (cfg.verbose && !cfg.trace) return fail("run", "-v and --quiet contradict each other");
  if (sh.scheduler.empty()) return fail("run", "no commands queued (use 'sched add COMMAND')");

  printf("Scheduling %zu real process(es): %s\n", sh.scheduler.workload().size(), Scheduler::describe(cfg).c_str());
  if (cfg.trace) printf("%7s  %-8s %-44s %s\n", "TIME", "EVENT", "DETAIL", "READY QUEUE");
  fflush(stdout);

  SchedResult r = sh.scheduler.run(cfg, stdout, sh.cpu, &sh.kern);
  Scheduler::print_report(r, stdout);
  // An interrupted run reports 128+signal, the convention used for any job
  // that ended because of a signal.
  int rc = r.interrupted ? 128 + (r.abort_signal ? r.abort_signal : SIGINT) : (r.over_budget ? 1 : 0);
  sh.scheduler.last = std::move(r);
  sh.schedule_tick();                                  // the shell's own jobs resume
  return rc;
}

int cmd_compare(Shell& sh, const Args& a) {
  std::vector<long> quanta = {50, 200};
  SchedConfig base;
  base.trace = false;
  bool q_given = false, np_given = false;
  for (size_t i = 2; i < a.size(); ++i) {
    if (a[i] == "-q") {
      if (i + 1 >= a.size()) return fail("compare", "-q needs a list such as 50,200");
      quanta.clear();
      std::string list = a[++i], tok;
      for (size_t k = 0; k <= list.size(); ++k) {
        if (k == list.size() || list[k] == ',') {
          long v;
          if (!parse_num(tok, v, 1, 600000)) return fail("compare", "invalid time slice '" + tok + "' in the list");
          quanta.push_back(v);
          tok.clear();
        } else {
          tok += list[k];
        }
      }
      if (quanta.size() > 6) return fail("compare", "at most 6 time slices (each one is a real run)");
    } else {
      std::string err = parse_run_options(a, i, base, q_given, np_given);
      if (!err.empty()) return fail("compare", err);
      break;
    }
  }
  if (sh.scheduler.empty()) return fail("compare", "no commands queued (use 'sched add COMMAND')");

  struct Row { std::string label; SchedConfig cfg; };
  std::vector<Row> rows;
  auto make = [&](PolicyKind k) { SchedConfig c = base; c.policy = k; c.trace = false; c.verbose = false; return c; };
  rows.push_back({"FCFS", make(PolicyKind::FCFS)});
  for (long q : quanta) { SchedConfig c = make(PolicyKind::RoundRobin); c.quantum_ms = q; rows.push_back({"RR q=" + std::to_string(q), c}); }
  rows.push_back({"Priority (preemptive)", make(PolicyKind::Priority)});
  { SchedConfig c = make(PolicyKind::Priority); c.preemptive = false; rows.push_back({"Priority (non-preempt)", c}); }

  printf("Replaying %zu real process(es) under %zu policies; switch cost %ld ms\n",
         sh.scheduler.workload().size(), rows.size(), base.switch_cost_ms);
  printf("  %-24s %9s %9s %9s %9s %9s %7s\n", "POLICY", "AVG WAIT", "AVG TURN", "AVG RESP", "SWITCHES", "MAKESPAN", "CPU%");
  fflush(stdout);

  SchedResult last;
  bool have = false;
  for (const Row& row : rows) {
    SchedResult r = sh.scheduler.run(row.cfg, stdout, sh.cpu, &sh.kern);
    printf("  %-24s %9.1f %9.1f %9.1f %9d %9ld %6.1f%%\n", row.label.c_str(), r.avg_waiting_ms(),
           r.avg_turnaround_ms(), r.avg_response_ms(), r.context_switches, r.makespan_ms, r.cpu_utilization());
    fflush(stdout);
    bool stop = r.interrupted;
    last = std::move(r);
    have = true;
    if (stop) { fprintf(stderr, "sched compare: interrupted\n"); break; }
  }
  if (have) sh.scheduler.last = std::move(last);
  sh.schedule_tick();
  return 0;
}

}  // namespace

int builtin_sched(Shell& sh, const Args& a) {
  if (a.size() < 2 || a[1] == "help" || a[1] == "-h" || a[1] == "--help") {
    usage();
    return a.size() < 2 ? 1 : 0;
  }
  const std::string& sub = a[1];
  if (sub == "live") return cmd_live(sh, a);
  if (sub == "policy") return cmd_policy(sh, a);
  if (sub == "default") return cmd_default(sh, a);
  if (sub == "trace") return cmd_trace(sh, a);
  if (sub == "ps") return cmd_ps(sh);
  if (sub == "add") return cmd_add(sh, a);
  if (sub == "list") return cmd_list(sh);
  if (sub == "clear") { sh.scheduler.clear(); puts("experiment queue cleared"); return 0; }
  if (sub == "remove") {
    if (a.size() != 3) return fail("remove", "usage: sched remove ID");
    long id;
    if (!parse_num(a[2], id, 1, 999999)) return fail("remove", "invalid task id '" + a[2] + "'");
    if (!sh.scheduler.remove((int)id)) return fail("remove", "no queued task with id " + a[2]);
    printf("removed task %ld\n", id);
    return 0;
  }
  if (sub == "run") return cmd_run(sh, a);
  if (sub == "compare") return cmd_compare(sh, a);
  if (sub == "stats") {
    if (!sh.scheduler.last) return fail("stats", "no run yet (use 'sched run')");
    Scheduler::print_report(*sh.scheduler.last, stdout);
    return 0;
  }
  fprintf(stderr, "sched: unknown subcommand '%s' (try 'sched help')\n", sub.c_str());
  return 2;
}
