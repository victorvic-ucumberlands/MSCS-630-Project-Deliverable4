// cpu_sched.hpp - the shell's resident CPU scheduler.
//
// One instance of CpuScheduler lives in the Shell for the whole session and
// decides which of the shell's child processes may use the CPU.  Every command
// the shell starts (an ordinary command typed at the prompt, a background job,
// or a task of a `sched run` experiment) is created STOPPED and handed to it
// with admit(); from then on only the scheduler continues or stops it.
//
//   Ready    the process is stopped (SIGSTOP, kernel state 'T') and waits in
//            the ready queue of the current policy;
//   Running  the scheduler continued it (SIGCONT): it holds the CPU;
//   Blocked  it held the CPU but went to sleep in the kernel (sleep, waiting
//            for input, disk ...).  It is left continued so the kernel can wake
//            it, and the CPU is given to someone else.  When it becomes
//            runnable again it re-enters the ready queue - or takes the CPU
//            straight away if the CPU is idle;
//   Parked   set aside while a `sched run` experiment owns the CPU.
//
// The engine is event driven: the driver (the shell's main loop, or the batch
// harness in scheduler.cpp) calls tick() whenever something may have changed
// and sleeps at most timeout_ms() between calls.  tick() enforces the time
// slice, notices processes that blocked or woke up, applies priority
// preemption, and dispatches the next process.  The driver reaps exited
// children itself and reports them with exited().
//
// Mutual exclusion: at most one admitted process is ever continued and
// runnable at a time.  The one exception is a Blocked process that wakes up:
// it runs until the next probe (at most kProbeMs) notices it and stops it.
#pragma once

#include <sys/resource.h>
#include <sys/types.h>

#include <functional>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "job.hpp"

enum class PolicyKind { FCFS, RoundRobin, Priority };

// How the CPU is shared.
struct CpuConfig {
  PolicyKind policy = PolicyKind::RoundRobin;
  long quantum_ms = 100;        // Round-Robin time slice
  bool preemptive = true;       // Priority: a more urgent ready process takes the CPU at once
  long switch_cost_ms = 0;      // extra delay charged each time the CPU changes hands
  bool block_detect = true;     // give the CPU away when the running process blocks
};

std::string describe(const CpuConfig& c);

// The scheduler's record of one admitted process.
struct CpuEntry {
  Job* pcb = nullptr;           // process-control block, owned by the driver
  int tag = -1;                 // driver's own identifier (job id / task index)
  long arrival_key = 0;         // first-come-first-served key among equal priorities
  unsigned long seq = 0;        // final tie-breaker (submission order)
  enum class State { Ready, Running, Blocked, Parked } state = State::Ready;
  long since_ms = 0;            // when it entered its current state
  long slice_used_ms = 0;       // CPU time used in the current time slice
  int  idle_probes = 0;         // consecutive probes that found nothing runnable
  long last_probe_ms = 0;
};

const char* to_string(CpuEntry::State s);

// Short label for a command line: the program name plus as many arguments as
// fit in 15 characters ('~' marks omitted arguments).
std::string short_label(const std::vector<std::string>& argv);

// ---------------------------------------------------------------------------
// Scheduling policies: the "which process runs next" decision
// ---------------------------------------------------------------------------
class SchedPolicy {
 public:
  virtual ~SchedPolicy() = default;
  virtual void enqueue(CpuEntry* e) = 0;            // e became ready
  virtual CpuEntry* pick() = 0;                     // remove and return the next one
  virtual long time_slice() const { return 0; }     // 0 = no limit
  virtual bool should_preempt(const CpuEntry&) const { return false; }
  virtual std::vector<CpuEntry*> snapshot() const = 0;   // service order
  virtual bool show_priority() const { return false; }
  bool empty() const { return snapshot().empty(); }
};

std::unique_ptr<SchedPolicy> make_policy(const CpuConfig& cfg);

// ---------------------------------------------------------------------------
// Statistics (recorded while `record` is true, e.g. during an experiment)
// ---------------------------------------------------------------------------
struct GanttSegment {
  enum Kind { Task, Idle, Switch };
  Kind kind = Task;
  int tag = -1;
  long start = 0, end = 0;
};

struct CpuStats {
  long busy_ms = 0, idle_ms = 0, overhead_ms = 0;
  int context_switches = 0, preemptions = 0, blocks = 0, wakeups = 0;
  std::vector<GanttSegment> gantt;
  bool gantt_truncated = false;
};

// ---------------------------------------------------------------------------
// Process primitives shared by every driver
// ---------------------------------------------------------------------------
namespace proc {
long mono_ms();                    // CLOCK_MONOTONIC in ms
void sleep_ms(long ms);
char state(pid_t pid);             // kernel state of one process: R S D T Z ... or '-'
// True if any thread of `pid` or of any of its descendants is runnable ('R').
// A job's leader is often a shell waiting for its children, so looking at the
// leader alone would mistake a busy job for a blocked one.
bool tree_runnable(pid_t pid);
// The same walk with help from the shell's system-call server (Deliverable 3):
// hint(pid) is 0 for a process asleep waiting for the shell (a semaphore, page
// I/O), 1 for one whose request is queued for the shell (it is "in a system
// call", so it counts as running), -1 = look at /proc.
enum class TreeState { Runnable, Idle, WaitingForShell };
TreeState tree_state(pid_t pid, const std::function<int(pid_t)>& hint);
}  // namespace proc

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------
class CpuScheduler {
 public:
  static constexpr long kProbeMs = 5;      // how often running/blocked processes are examined

  // Event log: kind ("DISPATCH", "QUANTUM", ...) and a one-line detail.
  std::function<void(const char* kind, const std::string& detail)> log;
  // Terminal ownership hooks (the shell gives the terminal to the foreground
  // job only while that job is not stopped by the scheduler).
  std::function<void(Job&)> before_continue, after_stop;
  // The engine collected a child's final status itself (it exited at the very
  // moment it was being stopped).  The driver records it; it must not call
  // back into the scheduler from here.
  std::function<void(Job&, int status, const struct rusage&)> collected;
  // The process turned out to be stopped by somebody else (Ctrl-Z) when the
  // engine stopped it; it has been dropped from scheduling.
  std::function<void(Job&, int sig)> user_stopped;
  // Deliverable 3: what the shell's system-call server knows about a process
  // (see proc::tree_state) and, for the event log, what it is waiting for.
  // A process asleep waiting for the shell is marked BLOCKED at the next
  // tick without waiting for a second probe.
  std::function<int(pid_t)> pid_hint;
  std::function<std::string(pid_t)> wait_reason;
  void reprobe();                          // probe every process at the next tick
  void wake(pid_t pid);                    // the shell is about to wake `pid` (it was Blocked)

  void configure(const CpuConfig& cfg);    // change policy; the ready queue is rebuilt
  const CpuConfig& config() const { return cfg_; }

  // ---- events reported by the driver ----------------------------------
  void admit(Job& pcb, int tag, long arrival_key, unsigned long seq);  // process is stopped
  void exited(Job& pcb);                   // the driver reaped it
  void stopped_elsewhere(Job& pcb);        // the driver saw a stop the engine did not cause
  void forget(Job& pcb);                   // drop it without signalling (it is being killed)

  // ---- requests made on the user's behalf -----------------------------
  void stop_for_user(Job& pcb);            // kill -STOP / Ctrl-Z: stop it and drop it
  void deliver(Job& pcb, int sig);         // send a signal so that it is acted on promptly
  void renice(Job& pcb, int priority);

  // ---- the scheduling step --------------------------------------------
  void tick();
  long timeout_ms() const;                 // -1 = nothing to do until an event

  // ---- whole-scheduler operations -------------------------------------
  void park_all();                         // an experiment takes the CPU
  void unpark_all();
  void release_all();                      // scheduling turned off: continue everything
  void forget_all();                       // in a forked child: drop state, send nothing

  // ---- inspection ------------------------------------------------------
  bool manages(const Job& pcb) const { return find(pcb) != nullptr; }
  const CpuEntry* entry_of(const Job& pcb) const { return find(pcb); }
  Job* running() const { return running_ ? running_->pcb : nullptr; }
  std::vector<const CpuEntry*> entries() const;
  std::string ready_text() const;
  bool has_ready() const { return policy_ && !policy_->empty(); }
  bool has_blocked() const;
  size_t size() const { return entries_.size(); }

  // ---- statistics -------------------------------------------------------
  void reset_stats(long t0_ms);
  CpuStats stats;
  bool record = false;                     // keep stats and a Gantt chart
  long t0 = 0;                             // Gantt times are relative to this

 private:
  enum class StopResult { Stopped, UserStopped, Gone };

  CpuEntry* find(const Job& pcb) const;
  void remove(CpuEntry* e);
  void rebuild(CpuEntry* drop = nullptr);
  StopResult stop_confirm(CpuEntry* e, long now, int* sig = nullptr);
  void account_running(long now);
  void close_idle(long now);
  void open_idle(long now);
  void enter_ready(CpuEntry* e, long now);
  void give_cpu(CpuEntry* e, long now, bool send_cont);
  void wake_entry(CpuEntry* e, long now, const char* why);
  void segment(GanttSegment::Kind k, int tag, long s, long e);
  void emit(const char* kind, const std::string& detail);

  CpuConfig cfg_;
  std::unique_ptr<SchedPolicy> policy_ = make_policy(CpuConfig{});
  std::list<CpuEntry> entries_;            // stable addresses
  CpuEntry* running_ = nullptr;
  unsigned long last_seq_ = 0;             // who held the CPU last (context-switch counting)
  std::string last_label_;
  bool has_last_ = false;
  long idle_since_ = -1;
  std::vector<CpuEntry*> parked_order_;
};
