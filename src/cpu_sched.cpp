// cpu_sched.cpp - the resident CPU scheduler.  See cpu_sched.hpp.
//
// The three mechanisms the whole design rests on:
//   SIGSTOP / SIGCONT   take the CPU away from a process / give it back;
//   wait4(WUNTRACED)    confirm with the kernel that a process really stopped
//                       before another one is continued (signals are
//                       asynchronous, so sending SIGSTOP is not enough);
//   /proc/<pid>/...     find out whether a continued process is actually
//                       running or has gone to sleep in the kernel.
#include "cpu_sched.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <queue>

// ===========================================================================
// Process primitives
// ===========================================================================
namespace proc {

long mono_ms() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

void sleep_ms(long ms) {
  if (ms <= 0) return;
  timespec t{ms / 1000, (ms % 1000) * 1000000L};
  while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}

// Read a small /proc file into buf; returns the number of bytes (0 on error).
static ssize_t slurp(const char* path, char* buf, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t n = read(fd, buf, size - 1);
  close(fd);
  if (n < 0) n = 0;
  buf[n] = '\0';
  return n;
}

// The state letter of a /proc/.../stat line: the field after the command,
// which is in parentheses and may itself contain spaces or ')'.
static char stat_state(const char* path) {
  char buf[512];
  if (slurp(path, buf, sizeof buf) == 0) return '-';
  const char* close_paren = strrchr(buf, ')');
  if (!close_paren || !close_paren[1] || !close_paren[2]) return '-';
  return close_paren[2];
}

char state(pid_t pid) {
  if (pid <= 0) return '-';
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
  return stat_state(path);
}

bool tree_runnable(pid_t root) { return tree_state(root, nullptr) == TreeState::Runnable; }

TreeState tree_state(pid_t root, const std::function<int(pid_t)>& hint) {
  std::vector<pid_t> todo{root};
  bool waits_for_shell = false;
  int visited = 0;
  while (!todo.empty() && visited < 512) {
    pid_t p = todo.back();
    todo.pop_back();
    ++visited;
    int h = hint ? hint(p) : -1;
    if (h == 1) return TreeState::Runnable;          // its request is queued: it is in a system call
    if (h == 0) waits_for_shell = true;              // asleep until the shell answers
    char dir[64];
    snprintf(dir, sizeof dir, "/proc/%d/task", (int)p);
    DIR* d = opendir(dir);
    if (!d) continue;                              // already gone
    bool runnable = false;
    while (dirent* t = readdir(d)) {
      if (t->d_name[0] < '0' || t->d_name[0] > '9') continue;
      char path[384];                              // d_name is at most 255 bytes
      snprintf(path, sizeof path, "%s/%s/stat", dir, t->d_name);
      if (h != 0 && stat_state(path) == 'R') { runnable = true; break; }   // a thread is on/for a CPU
      snprintf(path, sizeof path, "%s/%s/children", dir, t->d_name);
      char kids[4096];
      if (slurp(path, kids, sizeof kids) > 0) {    // descendants: "123 456 "
        char* save = nullptr;
        for (char* tok = strtok_r(kids, " \n", &save); tok; tok = strtok_r(nullptr, " \n", &save))
          todo.push_back((pid_t)atoi(tok));
      }
    }
    closedir(d);
    if (runnable) return TreeState::Runnable;
    // Asked again AFTER reading its state: if it went to sleep in recv() in
    // between, its request is now queued for the shell (which is busy right
    // here, so it cannot have been answered) - it is in a system call, not
    // blocked.  Asking only before would race with that.
    if (h == -1 && hint && hint(p) == 1) return TreeState::Runnable;
  }
  return waits_for_shell ? TreeState::WaitingForShell : TreeState::Idle;
}

}  // namespace proc

// ===========================================================================
// Policies
// ===========================================================================
namespace {

// FCFS and Round-Robin share one FIFO queue.  Round-Robin is "FIFO plus a
// time slice": a process that uses up its slice goes to the BACK of the queue.
// FCFS is the same queue with no slice, so a process keeps the CPU until it
// finishes or blocks.
class FifoPolicy : public SchedPolicy {
 public:
  explicit FifoPolicy(long quantum) : quantum_(quantum) {}
  void enqueue(CpuEntry* e) override { q_.push_back(e); }
  CpuEntry* pick() override {
    if (q_.empty()) return nullptr;
    CpuEntry* e = q_.front();
    q_.pop_front();
    return e;
  }
  long time_slice() const override { return quantum_; }
  std::vector<CpuEntry*> snapshot() const override { return {q_.begin(), q_.end()}; }

 private:
  long quantum_;                 // 0 = unlimited (FCFS)
  std::deque<CpuEntry*> q_;
};

// Priority: a binary heap.  Smaller priority number first; among equal
// priorities the process that ARRIVED first wins (first come, first served);
// the submission order breaks any remaining tie.  The original arrival is
// compared, not the moment a process was put back, so a preempted process
// resumes ahead of later arrivals of the same priority.
struct HeapOrder {
  // std::priority_queue keeps the "largest" element on top, so "less" has to
  // mean "serve later".
  bool operator()(const CpuEntry* a, const CpuEntry* b) const {
    if (a->pcb->priority != b->pcb->priority) return a->pcb->priority > b->pcb->priority;
    if (a->arrival_key != b->arrival_key) return a->arrival_key > b->arrival_key;
    return a->seq > b->seq;
  }
};

class PriorityPolicy : public SchedPolicy {
 public:
  explicit PriorityPolicy(bool preemptive) : preemptive_(preemptive) {}
  void enqueue(CpuEntry* e) override { heap_.push(e); }
  CpuEntry* pick() override {
    if (heap_.empty()) return nullptr;
    CpuEntry* e = heap_.top();
    heap_.pop();
    return e;
  }
  // Strictly more urgent only: an equal-priority process must wait its turn,
  // or equal-priority processes would keep interrupting each other.
  bool should_preempt(const CpuEntry& running) const override {
    return preemptive_ && !heap_.empty() && heap_.top()->pcb->priority < running.pcb->priority;
  }
  std::vector<CpuEntry*> snapshot() const override {
    auto copy = heap_;
    std::vector<CpuEntry*> v;
    while (!copy.empty()) { v.push_back(copy.top()); copy.pop(); }
    return v;
  }
  bool show_priority() const override { return true; }

 private:
  bool preemptive_;
  std::priority_queue<CpuEntry*, std::vector<CpuEntry*>, HeapOrder> heap_;
};

std::string pid_str(const Job& p) { return std::to_string((int)p.pid); }

// The label shown for a process in the log and the ready queue.
const std::string& name(const Job& p) { return p.sched_label.empty() ? p.command : p.sched_label; }

}  // namespace

std::unique_ptr<SchedPolicy> make_policy(const CpuConfig& cfg) {
  switch (cfg.policy) {
    case PolicyKind::FCFS:       return std::make_unique<FifoPolicy>(0);
    case PolicyKind::RoundRobin: return std::make_unique<FifoPolicy>(cfg.quantum_ms);
    case PolicyKind::Priority:   return std::make_unique<PriorityPolicy>(cfg.preemptive);
  }
  return nullptr;
}

std::string describe(const CpuConfig& c) {
  std::string s;
  switch (c.policy) {
    case PolicyKind::FCFS: s = "FCFS (first come, first served, run to completion)"; break;
    case PolicyKind::RoundRobin: s = "Round-Robin, time slice " + std::to_string(c.quantum_ms) + " ms"; break;
    case PolicyKind::Priority:
      s = std::string("Priority, ") + (c.preemptive ? "preemptive" : "non-preemptive") +
          " (lower number = higher priority, ties first-come-first-served)";
      break;
  }
  if (c.switch_cost_ms > 0) s += ", context-switch cost " + std::to_string(c.switch_cost_ms) + " ms";
  if (!c.block_detect) s += ", block detection off";
  return s;
}

std::string short_label(const std::vector<std::string>& argv) {
  if (argv.empty()) return "?";
  std::string s = argv[0];
  size_t slash = s.find_last_of('/');
  if (slash != std::string::npos) s = s.substr(slash + 1);   // drop the directory
  if (s.size() > 15) s = s.substr(0, 14) + "~";
  for (size_t i = 1; i < argv.size(); ++i) {                 // add arguments while they fit
    if (s.size() + 1 + argv[i].size() > 15) { s += "~"; break; }   // '~' = arguments omitted
    s += " " + argv[i];
  }
  return s;
}

const char* to_string(CpuEntry::State s) {
  switch (s) {
    case CpuEntry::State::Ready:   return "READY";
    case CpuEntry::State::Running: return "RUN";
    case CpuEntry::State::Blocked: return "BLOCKED";
    case CpuEntry::State::Parked:  return "PARKED";
  }
  return "?";
}

// ===========================================================================
// Bookkeeping helpers
// ===========================================================================
void CpuScheduler::emit(const char* kind, const std::string& detail) {
  if (log) log(kind, detail);
}

void CpuScheduler::segment(GanttSegment::Kind k, int tag, long s, long e) {
  if (!record) return;
  s -= t0;
  e -= t0;
  if (e <= s) return;
  if (!stats.gantt.empty()) {                     // merge touching segments of the same kind
    GanttSegment& b = stats.gantt.back();
    if (b.kind == k && b.tag == tag && b.end == s) { b.end = e; return; }
  }
  if (stats.gantt.size() >= 20000) { stats.gantt_truncated = true; return; }
  stats.gantt.push_back({k, tag, s, e});
}

void CpuScheduler::open_idle(long now) {
  if (record && idle_since_ < 0) idle_since_ = now;
}

void CpuScheduler::close_idle(long now) {
  if (idle_since_ < 0) return;
  segment(GanttSegment::Idle, -1, idle_since_, now);
  stats.idle_ms += now - idle_since_;
  idle_since_ = -1;
}

// Credit the running process with the time it has just held the CPU.
void CpuScheduler::account_running(long now) {
  if (!running_) return;
  long d = std::max(0L, now - running_->since_ms);
  running_->pcb->dispatched_ms += d;
  running_->slice_used_ms += d;
  stats.busy_ms += d;
  segment(GanttSegment::Task, running_->tag, running_->since_ms, now);
  running_->since_ms = now;
}

void CpuScheduler::enter_ready(CpuEntry* e, long now) {
  e->state = CpuEntry::State::Ready;
  e->since_ms = now;
  policy_->enqueue(e);
}

CpuEntry* CpuScheduler::find(const Job& pcb) const {
  for (const auto& e : entries_)
    if (e.pcb == &pcb) return const_cast<CpuEntry*>(&e);
  return nullptr;
}

bool CpuScheduler::has_blocked() const {
  for (const auto& e : entries_)
    if (e.state == CpuEntry::State::Blocked) return true;
  return false;
}

std::vector<const CpuEntry*> CpuScheduler::entries() const {
  std::vector<const CpuEntry*> v;
  for (const auto& e : entries_) v.push_back(&e);
  return v;
}

// Rebuild the ready queue under the current policy, optionally leaving one
// entry out.  Used to remove an arbitrary entry (neither std::deque in FIFO
// order nor std::priority_queue supports that directly) and after a priority
// changes.  The queue holds at most a few dozen processes, so this is cheap.
void CpuScheduler::rebuild(CpuEntry* drop) {
  auto order = policy_->snapshot();
  policy_ = make_policy(cfg_);
  for (CpuEntry* e : order)
    if (e != drop) policy_->enqueue(e);
}

void CpuScheduler::remove(CpuEntry* e) {
  if (e->state == CpuEntry::State::Ready) rebuild(e);
  if (running_ == e) running_ = nullptr;
  parked_order_.erase(std::remove(parked_order_.begin(), parked_order_.end(), e), parked_order_.end());
  for (auto it = entries_.begin(); it != entries_.end(); ++it)
    if (&*it == e) { entries_.erase(it); return; }
}

// Stop a continued process and wait until the kernel confirms it.  Returns
// UserStopped (with the signal in `sig`) when the stop that arrived was not
// ours - the user pressed Ctrl-Z at that instant - and Gone when the process
// exited instead (its status is then passed to `collected`).
CpuScheduler::StopResult CpuScheduler::stop_confirm(CpuEntry* e, long, int* sig) {
  Job& p = *e->pcb;
  kill(-p.pgid, SIGSTOP);
  for (int i = 0; i < 20000; ++i) {                // bounded: never hang the shell
    int st = 0;
    struct rusage ru{};
    pid_t got = wait4(p.pid, &st, WUNTRACED | WNOHANG, &ru);
    if (got < 0) {
      if (errno == EINTR) continue;
      return StopResult::Gone;                     // somebody else reaped it
    }
    if (got > 0) {
      if (WIFSTOPPED(st)) {
        if (WSTOPSIG(st) == SIGSTOP) return StopResult::Stopped;
        if (sig) *sig = WSTOPSIG(st);
        return StopResult::UserStopped;
      }
      if (collected) collected(p, st, ru);         // it exited at this very moment
      return StopResult::Gone;
    }
    // No report yet.  If the kernel already shows it stopped, the report was
    // consumed earlier (it stopped itself just before): accept that.
    if (i > 50 && proc::state(p.pid) == 'T') return StopResult::Stopped;
    if (i > 20) usleep(100);
  }
  return StopResult::Stopped;
}

// Hand the CPU to `e`.  send_cont=false is used for a process that woke up
// while the CPU was idle: it is already running, so there is nothing to send.
void CpuScheduler::give_cpu(CpuEntry* e, long now, bool send_cont) {
  Job& p = *e->pcb;
  if (has_last_ && last_seq_ != e->seq) {
    stats.context_switches++;
    if (cfg_.switch_cost_ms > 0 && send_cont) {    // the dispatcher's own work
      close_idle(now);
      emit("SWITCH", "context switch " + last_label_ + " -> " + name(p) + " costs " +
                         std::to_string(cfg_.switch_cost_ms) + " ms");
      proc::sleep_ms(cfg_.switch_cost_ms);
      long after = proc::mono_ms();
      segment(GanttSegment::Switch, -1, now, after);
      stats.overhead_ms += after - now;
      now = after;
    }
  }
  close_idle(now);
  if (e->state == CpuEntry::State::Ready || e->state == CpuEntry::State::Parked)
    p.ready_ms += std::max(0L, now - e->since_ms);
  else if (e->state == CpuEntry::State::Blocked)
    p.blocked_ms += std::max(0L, now - e->since_ms);

  e->state = CpuEntry::State::Running;
  e->since_ms = now;
  e->idle_probes = 0;
  e->last_probe_ms = now;
  if (p.dispatches == 0) p.first_run = Job::Clock::now();
  ++p.dispatches;
  running_ = e;
  last_seq_ = e->seq;
  last_label_ = name(p);
  has_last_ = true;

  if (before_continue) before_continue(p);         // e.g. hand it the terminal first
  if (send_cont) {
    kill(-p.pgid, SIGCONT);                        // <-- the process runs from here
    long sl = policy_->time_slice();
    emit("DISPATCH", name(p) + ": gets the CPU (SIGCONT pid " + pid_str(p) + ")" +
                         (sl > 0 ? ", slice " + std::to_string(sl - e->slice_used_ms) + " ms"
                                 : std::string(", no slice limit")));
  } else {
    emit("WAKE", name(p) + ": woke up and takes the idle CPU");
  }
}

// ===========================================================================
// Configuration and events
// ===========================================================================
void CpuScheduler::configure(const CpuConfig& cfg) {
  auto order = policy_->snapshot();
  cfg_ = cfg;
  policy_ = make_policy(cfg_);
  for (CpuEntry* e : order) policy_->enqueue(e);
}

void CpuScheduler::admit(Job& pcb, int tag, long arrival_key, unsigned long seq) {
  entries_.emplace_back();
  CpuEntry* e = &entries_.back();
  e->pcb = &pcb;
  e->tag = tag;
  e->arrival_key = arrival_key;
  e->seq = seq;
  pcb.scheduled = true;
  enter_ready(e, proc::mono_ms());
}

// Close the books on an entry that is leaving (exited, stopped elsewhere,
// forgotten) and remove it.
static void settle(CpuEntry* e, long now) {
  long d = std::max(0L, now - e->since_ms);
  if (e->state == CpuEntry::State::Ready || e->state == CpuEntry::State::Parked) e->pcb->ready_ms += d;
  else if (e->state == CpuEntry::State::Blocked) e->pcb->blocked_ms += d;
}

void CpuScheduler::exited(Job& pcb) {
  CpuEntry* e = find(pcb);
  if (!e) return;
  long now = proc::mono_ms();
  if (running_ == e) {
    account_running(now);
    running_ = nullptr;
    open_idle(now);
  } else {
    settle(e, now);
  }
  remove(e);
}

void CpuScheduler::stopped_elsewhere(Job& pcb) {
  CpuEntry* e = find(pcb);
  if (!e) return;
  long now = proc::mono_ms();
  if (running_ == e) {
    account_running(now);
    running_ = nullptr;
    open_idle(now);
    if (after_stop) after_stop(pcb);
  } else {
    settle(e, now);
  }
  remove(e);
  emit("STOP", name(pcb) + ": stopped by the user, no longer scheduled");
}

void CpuScheduler::forget(Job& pcb) {
  CpuEntry* e = find(pcb);
  if (!e) return;
  long now = proc::mono_ms();
  if (running_ == e) {
    account_running(now);
    running_ = nullptr;
    open_idle(now);
  } else {
    settle(e, now);
  }
  remove(e);
}

void CpuScheduler::stop_for_user(Job& pcb) {
  CpuEntry* e = find(pcb);
  if (!e) return;
  long now = proc::mono_ms();
  if (e->state == CpuEntry::State::Running || e->state == CpuEntry::State::Blocked) {
    bool was_running = (running_ == e);
    if (was_running) account_running(now);
    else settle(e, now);
    int sig = 0;
    StopResult r = stop_confirm(e, now, &sig);
    if (was_running) { running_ = nullptr; open_idle(now); }
    if (r != StopResult::Gone && after_stop) after_stop(pcb);
  } else {
    settle(e, now);                                // already stopped in the queue
  }
  remove(e);
  emit("STOP", name(pcb) + ": stopped by the user, removed from the ready queue");
}

// Deliver a signal so that the process acts on it promptly.  A process
// waiting in the ready queue is stopped, and a stopped process cannot act on
// most signals until it is continued; leaving the signal pending until the
// process's normal turn could take arbitrarily long under priority
// scheduling.  So, like a kernel delivering a signal, the scheduler gives it
// the CPU at once - the running process is preempted - and the signal is
// handled immediately.  If the process survives (it handles or ignores the
// signal) it simply carries on as the running process.
void CpuScheduler::deliver(Job& pcb, int sig) {
  CpuEntry* e = find(pcb);
  if (!e || e->state != CpuEntry::State::Ready) {
    kill(-pcb.pgid, sig);
    return;
  }
  long now = proc::mono_ms();
  if (running_) {
    CpuEntry* r = running_;
    account_running(now);
    int s = 0;
    StopResult res = stop_confirm(r, now, &s);
    running_ = nullptr;
    open_idle(now);
    if (res == StopResult::Stopped) {
      if (after_stop) after_stop(*r->pcb);
      r->slice_used_ms = 0;
      r->pcb->preemptions++;
      stats.preemptions++;
      enter_ready(r, now);
      emit("PREEMPT", name(*r->pcb) + ": preempted so a signal can be delivered (SIGSTOP)");
    } else {
      Job& rp = *r->pcb;
      remove(r);
      if (res == StopResult::UserStopped && user_stopped) user_stopped(rp, s);
    }
  }
  rebuild(e);                                      // take it out of the queue
  kill(-pcb.pgid, sig);                            // pending until it is continued...
  emit("SIGNAL", name(pcb) + ": signal " + std::to_string(sig) + " (" + strsignal(sig) +
                     ") delivered; given the CPU at once to act on it");
  give_cpu(e, proc::mono_ms(), true);              // ...which happens now
}

// A Blocked process is runnable again: it takes the idle CPU, or it is
// stopped and joins the ready queue (where priority preemption may still hand
// it the CPU in the same tick).
void CpuScheduler::wake_entry(CpuEntry* e, long now, const char* why) {
  stats.wakeups++;
  if (!running_ && !has_ready()) {
    give_cpu(e, now, false);
    return;
  }
  e->pcb->blocked_ms += std::max(0L, now - e->since_ms);
  int sig = 0;
  StopResult r = stop_confirm(e, now, &sig);
  if (r == StopResult::Stopped) {
    if (after_stop) after_stop(*e->pcb);
    enter_ready(e, now);
    emit("WAKE", name(*e->pcb) + (why ? std::string(": ") + why + "; stopped (SIGSTOP) and queued"
                                      : std::string(": woke up; stopped (SIGSTOP) and queued")));
  } else {
    Job& p = *e->pcb;
    e->since_ms = now;
    remove(e);
    if (r == StopResult::UserStopped && user_stopped) user_stopped(p, sig);
  }
}

// The shell is about to answer a request that `pid` sleeps on (a semaphore was
// posted, its page arrived).  Like a kernel putting a woken task on the run
// queue, the scheduler decides BEFORE the process can run: if another process
// holds the CPU it is stopped first, so the two never run side by side.
void CpuScheduler::wake(pid_t pid) {
  for (auto& e : entries_) {
    if (!e.pcb || e.pcb->pid != pid || e.state != CpuEntry::State::Blocked) continue;
    long now = proc::mono_ms();
    e.last_probe_ms = now;
    wake_entry(&e, now, "its system call was answered (woken by the shell)");
    return;
  }
}

void CpuScheduler::reprobe() {
  for (auto& e : entries_) e.last_probe_ms = 0;
}

void CpuScheduler::renice(Job& pcb, int priority) {
  pcb.priority = priority;
  CpuEntry* e = find(pcb);
  if (e && e->state == CpuEntry::State::Ready) rebuild();   // heap order depends on it
}

// ===========================================================================
// The scheduling step
// ===========================================================================
void CpuScheduler::tick() {
  long now = proc::mono_ms();

  // 1. Has the running process gone to sleep in the kernel?  Two consecutive
  //    probes finding nothing runnable in its process tree means it really is
  //    blocked (a single sample could catch a brief pause, e.g. a write).
  if (running_ && cfg_.block_detect && now - running_->last_probe_ms >= kProbeMs) {
    CpuEntry* e = running_;
    e->last_probe_ms = now;
    proc::TreeState ts = proc::tree_state(e->pcb->pid, pid_hint);
    if (ts == proc::TreeState::Runnable) {
      e->idle_probes = 0;
    } else if (ts == proc::TreeState::WaitingForShell || ++e->idle_probes >= 2) {
      std::string why = wait_reason ? wait_reason(e->pcb->pid) : "";
      account_running(now);
      e->state = CpuEntry::State::Blocked;
      e->since_ms = now;
      e->slice_used_ms = 0;                        // a fresh slice when it next runs
      e->idle_probes = 0;
      running_ = nullptr;
      open_idle(now);
      stats.blocks++;
      if (!why.empty())
        emit("BLOCK", name(*e->pcb) + ": waits for " + why + ", CPU released");
      else
        emit("BLOCK", name(*e->pcb) + ": blocked in the kernel (state " +
                          std::string(1, proc::state(e->pcb->pid)) + "), CPU released");
    }
  }

  // 2. Has its time slice run out?  (Round-Robin)
  if (running_) {
    long sl = policy_->time_slice();
    if (sl > 0 && running_->slice_used_ms + (now - running_->since_ms) >= sl) {
      CpuEntry* e = running_;
      account_running(now);
      int sig = 0;
      StopResult r = stop_confirm(e, now, &sig);
      running_ = nullptr;
      open_idle(now);
      if (r == StopResult::Stopped) {
        if (after_stop) after_stop(*e->pcb);
        e->slice_used_ms = 0;
        e->pcb->preemptions++;
        stats.preemptions++;
        enter_ready(e, now);
        emit("QUANTUM", name(*e->pcb) + ": " + std::to_string(sl) +
                            " ms slice used up (SIGSTOP), moved to back of queue");
      } else {
        Job& p = *e->pcb;
        if (r == StopResult::UserStopped && after_stop) after_stop(p);
        remove(e);
        if (r == StopResult::UserStopped && user_stopped) user_stopped(p, sig);
      }
    }
  }

  // 3. Has a blocked process woken up?  If the CPU is idle it simply keeps
  //    running; otherwise it is stopped and joins the ready queue, where the
  //    policy decides (priority preemption may hand it the CPU in step 4).
  std::vector<CpuEntry*> blocked;
  for (auto& e : entries_)
    if (e.state == CpuEntry::State::Blocked) blocked.push_back(&e);
  for (CpuEntry* e : blocked) {
    if (now - e->last_probe_ms < kProbeMs) continue;
    e->last_probe_ms = now;
    if (proc::tree_state(e->pcb->pid, pid_hint) != proc::TreeState::Runnable) continue;
    wake_entry(e, now, nullptr);
  }

  // 4. Priority preemption: a strictly more urgent process is ready.
  if (running_ && policy_->should_preempt(*running_)) {
    CpuEntry* e = running_;
    account_running(now);
    int sig = 0;
    StopResult r = stop_confirm(e, now, &sig);
    running_ = nullptr;
    open_idle(now);
    if (r == StopResult::Stopped) {
      if (after_stop) after_stop(*e->pcb);
      e->slice_used_ms = 0;
      e->pcb->preemptions++;
      stats.preemptions++;
      enter_ready(e, now);
      emit("PREEMPT", name(*e->pcb) + ": preempted by higher priority (SIGSTOP), held " +
                          std::to_string(e->pcb->dispatched_ms) + " ms so far");
    } else {
      Job& p = *e->pcb;
      remove(e);
      if (r == StopResult::UserStopped && user_stopped) user_stopped(p, sig);
    }
  }

  // 5. Dispatch: the CPU is free, give it to the process the policy picks.
  if (!running_) {
    CpuEntry* next = policy_->pick();
    if (next) give_cpu(next, proc::mono_ms(), true);
  }
}

long CpuScheduler::timeout_ms() const {
  long now = proc::mono_ms();
  long t = -1;
  auto take = [&](long v) {
    if (v < 0) v = 0;
    if (t < 0 || v < t) t = v;
  };
  if (!running_ && has_ready()) return 0;
  if (running_) {
    long sl = policy_->time_slice();
    if (sl > 0) take(sl - (running_->slice_used_ms + (now - running_->since_ms)));
    if (cfg_.block_detect) take(kProbeMs - (now - running_->last_probe_ms));
  }
  for (const auto& e : entries_)
    if (e.state == CpuEntry::State::Blocked) take(kProbeMs - (now - e.last_probe_ms));
  return t;
}

// ===========================================================================
// Whole-scheduler operations
// ===========================================================================
// A `sched run` experiment takes the CPU for itself: everything currently
// scheduled is stopped and set aside, in its current service order.
void CpuScheduler::park_all() {
  long now = proc::mono_ms();
  std::vector<CpuEntry*> order = policy_->snapshot();
  std::vector<CpuEntry*> active;
  if (running_) active.push_back(running_);
  for (auto& e : entries_)
    if (e.state == CpuEntry::State::Blocked) active.push_back(&e);
  for (CpuEntry* e : active) {
    bool was_running = (running_ == e);
    if (was_running) account_running(now);
    else settle(e, now);
    int sig = 0;
    StopResult r = stop_confirm(e, now, &sig);
    if (was_running) running_ = nullptr;
    if (r == StopResult::Stopped) {
      if (after_stop) after_stop(*e->pcb);
      e->since_ms = now;
      order.push_back(e);
    } else {
      Job& p = *e->pcb;
      remove(e);
      if (r == StopResult::UserStopped && user_stopped) user_stopped(p, sig);
    }
  }
  for (CpuEntry* e : order) e->state = CpuEntry::State::Parked;   // Ready keeps its since_ms
  parked_order_ = order;
  policy_ = make_policy(cfg_);
  running_ = nullptr;
  idle_since_ = -1;
}

void CpuScheduler::unpark_all() {
  long now = proc::mono_ms();
  for (CpuEntry* e : parked_order_) {
    e->pcb->ready_ms += std::max(0L, now - e->since_ms);
    enter_ready(e, now);
  }
  parked_order_.clear();
}

// Scheduling switched off: every process the scheduler was holding back is
// continued and from now on the kernel alone decides when it runs.
void CpuScheduler::release_all() {
  long now = proc::mono_ms();
  for (auto& e : entries_) {
    if (&e == running_) {
      account_running(now);
    } else {
      settle(&e, now);
      if (e.state == CpuEntry::State::Ready || e.state == CpuEntry::State::Parked)
        kill(-e.pcb->pgid, SIGCONT);
    }
    e.pcb->scheduled = false;
  }
  forget_all();
}

void CpuScheduler::forget_all() {
  entries_.clear();
  parked_order_.clear();
  policy_ = make_policy(cfg_);
  running_ = nullptr;
  has_last_ = false;
  idle_since_ = -1;
}

std::string CpuScheduler::ready_text() const {
  std::string s = "[";
  bool first = true;
  for (const CpuEntry* e : policy_->snapshot()) {   // ", " because labels may contain spaces
    if (!first) s += ", ";
    first = false;
    s += name(*e->pcb);
    if (policy_->show_priority()) s += "(" + std::to_string(e->pcb->priority) + ")";
  }
  return s + "]";
}

void CpuScheduler::reset_stats(long t0_ms) {
  stats = CpuStats{};
  t0 = t0_ms;
  idle_since_ = (record && !running_) ? t0_ms : -1;
}
