// job.hpp - Job record and job table.
//
// The Job struct is the shell's "process control block" (PCB-lite).  Deliverable 1
// only needs id/pid/state/command, but the record already carries the extra
// fields (priority, queue level, burst estimate, accounting times) that the
// scheduler of Deliverable 2 and the memory/sync modules of later deliverables
// will need, so they never have to change the shape of the record.
#pragma once

#include <sys/types.h>

#include <chrono>
#include <ctime>
#include <list>
#include <string>
#include <vector>

// Life-cycle of a job.  Real shell jobs start immediately and go straight to
// Running.  New/Ready are used by the scheduler (Deliverable 2): New = not yet
// arrived, Ready = waiting in the ready queue, Running = holds the CPU.
enum class JobState {
  New,         // record created, process not yet forked      (scheduler use)
  Ready,       // runnable, waiting for the CPU / a time slice  (scheduler use)
  Running,     // process exists and is runnable/running
  Stopped,     // suspended by SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU
  Done,        // exited normally (exit_status valid)
  Terminated   // killed by a signal (term_signal valid)
};

const char* to_string(JobState s);

struct Job {
  using Clock = std::chrono::steady_clock;

  // ---- identity ---------------------------------------------------------
  int id = 0;            // user-visible job number: "[1]", "%1" (lowest free number, reused after a job ends)
  unsigned long serial = 0;  // unique record number, never reused (key for history / scheduler statistics)
  pid_t pid = 0;         // process id of the (single) process in the job
  pid_t pgid = 0;        // process group id (== pid: each job leads its own group)
  std::string command;   // source text of the command, e.g. "sleep 30"

  // ---- state ------------------------------------------------------------
  JobState state = JobState::New;
  bool foreground = false;  // true while the shell is waiting on it
  int exit_status = -1;     // valid when state == Done
  int term_signal = 0;      // valid when state == Terminated
  int stop_signal = 0;      // last stop signal (valid when Stopped)
  bool notified = false;    // completion message already shown to the user

  // ---- scheduler-facing fields (used by the Deliverable 2 scheduler) ----
  // A scheduler-managed process is an ordinary child of the shell that the
  // shell itself decides when to run (cpu_sched.hpp).  It is either waiting in
  // the ready queue as a really stopped process (kernel state 'T'), holding
  // the CPU, or blocked in the kernel.  `state` above keeps its Deliverable 1
  // meaning (Running = alive and not stopped by the user); the fine-grained
  // CPU state lives in the scheduler's own entry for the process.
  bool scheduled = false;       // the shell's scheduler decides when it runs
  int  dispatches = 0;          // times the scheduler gave it the CPU
  int  preemptions = 0;         // times it lost the CPU before finishing
  long dispatched_ms = 0;       // total time it held the CPU
  long ready_ms = 0;            // total time it waited in the ready queue = WAITING TIME
  long blocked_ms = 0;          // total time it was blocked in the kernel (sleep, I/O)
  long sched_arrival_ms = 0;    // arrival key used for first-come-first-served tie-breaks
  std::string sched_label;      // short name shown by the scheduler (empty = command)
  int  priority = 0;            // 0..99, lower number = higher priority
  int  queue_level = 0;         // multilevel-feedback-queue level (future policies)
  long burst_estimate_ms = 0;   // predicted CPU burst (0 = unknown; future policies)

  // ---- accounting -------------------------------------------------------
  Clock::time_point arrival{};    // when the job entered the system
  Clock::time_point first_run{};  // first time it got the CPU (response time)
  Clock::time_point finish{};     // when it exited / was killed
  std::time_t submitted_wall = 0; // wall-clock submit time (for display)
  long cpu_user_ms = 0;           // user CPU time  (from wait4 rusage)
  long cpu_sys_ms = 0;            // system CPU time (from wait4 rusage)
  int  stop_count = 0;            // how many times it was suspended

  // ---- memory (Deliverable 3) --------------------------------------------
  // The shell's own paging statistics for a process live in the memory
  // manager (memory.hpp, `mem ps`).  These are the REAL kernel's figures for
  // the same process, from wait4's rusage, for comparison.
  long kern_minflt = 0;           // Linux minor page faults
  long kern_majflt = 0;           // Linux major page faults
  long kern_maxrss_kb = 0;        // Linux peak resident set size

  // ---- internals --------------------------------------------------------
  unsigned long use_seq = 0;  // recency counter: decides the "+" / "-" jobs

  bool finished() const { return state == JobState::Done || state == JobState::Terminated; }

  // Derived metrics (milliseconds).  Only meaningful once finished().
  long turnaround_ms() const;  // finish - arrival
  long response_ms() const;    // first_run - arrival
  long wait_ms() const;        // time in the ready queue (scheduled) / turnaround - cpu (otherwise)
};

// Owns every job record.  Active jobs live in a std::list (stable addresses, so
// Job* handed to callers stay valid while other jobs come and go); finished
// jobs are moved to a history vector that scheduler statistics can read later.
class JobTable {
 public:
  // Create a record for a freshly forked process.  Starts in Running state.
  Job& add(pid_t pid, pid_t pgid, const std::string& command, bool foreground);

  Job* find_by_id(int id);
  Job* find_by_pid(pid_t pid);

  // "Current" (%+) and "previous" (%-) job: stopped jobs first, then the most
  // recently used.  Returns nullptr when there is no such job.
  Job* current();
  Job* previous();

  // Mark a job as most-recently-used (after fg/bg/stop).
  void touch(Job& j) { j.use_seq = ++seq_; }

  // Active (not yet finished) jobs ordered by id.
  std::vector<Job*> active();
  bool has_stopped() const;
  bool empty() const { return active_.empty(); }

  // Move a finished job to the history and drop it from the active list.
  // The reference becomes invalid after this call.
  void retire(int id);

  const std::vector<Job>& history() const { return history_; }

 private:
  std::vector<Job*> by_recency();

  std::list<Job> active_;
  std::vector<Job> history_;
  unsigned long next_serial_ = 1;  // record serials are never reused within a session
  unsigned long seq_ = 0;
};
