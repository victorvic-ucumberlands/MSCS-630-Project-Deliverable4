// scheduler.hpp - `sched run`: controlled scheduling experiments.
//
// Every command the shell starts is already scheduled by the resident
// CpuScheduler (cpu_sched.hpp).  This module adds the experiment harness on
// top of it: a workload of commands is queued with `sched add` (each with a
// priority and an arrival time), and `sched run` executes the whole workload
// under one policy and prints a measured report.
//
// An experiment uses the SAME scheduler as everyday commands.  For the length
// of the run the shell's other scheduled jobs are parked (stopped and set
// aside), the scheduler is switched to the experiment's policy, and the
// workload's processes are created at their arrival times and admitted to it.
// Afterwards the previous policy is restored and the parked jobs resume.
#pragma once

#include <sys/types.h>

#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "cpu_sched.hpp"
#include "job.hpp"

class Kernel;

// One queued command plus its process-control block.
struct SchedTask {
  std::vector<std::string> argv;  // the command to exec
  std::string out_path;           // -o FILE: the task's stdout+stderr (empty = inherit)
  long arrival_ms = 0;            // -t MS: created this long after the run starts
  Job pcb;                        // id, label, priority, pid, timings, accounting
  bool spawned = false;           // the process has been created
  bool aborted = false;           // terminated because the run was cut short
};

// Settings of one experiment.
struct SchedConfig {
  PolicyKind policy = PolicyKind::RoundRobin;
  long quantum_ms = 100;          // Round-Robin time slice
  bool preemptive = true;         // Priority: preempt when a more urgent task is ready
  long switch_cost_ms = 0;        // charged each time the CPU changes hands
  bool block_detect = true;       // give the CPU away when the running task blocks
  long budget_ms = 120000;        // safety net: give up after this much wall time
  bool trace = true;              // print the scheduling event log
  bool verbose = false;           // add per-task state (and the kernel's own) to the log

  CpuConfig cpu() const { return {policy, quantum_ms, preemptive, switch_cost_ms, block_detect}; }
};

struct SchedResult {
  SchedConfig cfg;
  std::vector<SchedTask> tasks;       // final state of every task
  std::vector<GanttSegment> gantt;    // tag = index into tasks
  bool gantt_truncated = false;
  long makespan_ms = 0;               // from the start of the run to the last exit
  long busy_ms = 0;                   // some task held the CPU
  long idle_ms = 0;                   // nothing to run
  long overhead_ms = 0;               // charged context-switch cost
  int context_switches = 0;
  int preemptions = 0;                // SIGSTOPs for quantum expiry or priority
  int blocks = 0;                     // times the running task blocked in the kernel
  bool interrupted = false;           // Ctrl-C, or SIGTERM/SIGHUP to a background run
  int abort_signal = 0;
  bool over_budget = false;

  int finished_count() const;
  double avg_waiting_ms() const;      // mean time in the ready queue
  double avg_turnaround_ms() const;   // mean of (exit - arrival)
  double avg_response_ms() const;     // mean of (first dispatch - arrival)
  double cpu_utilization() const;     // busy / makespan
  double throughput_per_s() const;
};

class Scheduler {
 public:
  static constexpr size_t kMaxTasks = 64;        // real processes, so keep it modest
  static constexpr long kMaxArrivalMs = 600000;  // 10 minutes
  static constexpr long kMaxBudgetMs = 900000;   // 15 minutes

  std::string add(const SchedTask& t);           // "" on success, else the reason
  bool remove(int id);
  void clear() { tasks_.clear(); next_id_ = 1; }
  const std::vector<SchedTask>& workload() const { return tasks_; }
  bool empty() const { return tasks_.empty(); }

  // Execute the workload under `cfg` on the shell's scheduler `cpu`.  The
  // queued workload is left untouched, so it can be replayed.
  // `kern` (Deliverable 3) is the shell's system-call server: tasks that use
  // paged memory or semaphores are served while the experiment runs.
  SchedResult run(const SchedConfig& cfg, FILE* out, CpuScheduler& cpu, Kernel* kern = nullptr);

  std::optional<SchedResult> last;

  static void print_report(const SchedResult& r, FILE* out);
  static std::string describe(const SchedConfig& cfg) { return ::describe(cfg.cpu()); }

 private:
  std::vector<SchedTask> tasks_;
  int next_id_ = 1;
};
