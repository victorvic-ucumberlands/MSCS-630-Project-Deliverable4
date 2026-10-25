// sync.hpp - semaphores and mutexes kept by the shell for its processes
// (Deliverable 3).
//
// The shell is the "kernel" here: a semaphore is an object inside the shell,
// and a process operates on it with a request over its kernel connection
// (mkernel.h).  P() on a semaphore whose value is 0 is simply not answered:
// the process stays asleep in recv(), the scheduler sees it blocked and gives
// the CPU to someone else.  V() hands the semaphore directly to the waiter at
// the head of its FIFO queue and answers its request, which wakes it.  Because
// the hand-off goes to the longest waiter and the value never becomes visible
// to a newcomer in between, no waiter can be overtaken forever (no
// starvation), and the test-and-decrement is atomic because the shell
// performs it on one thread.
//
// Two kinds:
//   semaphore  a counting semaphore (value >= 0), any process may post;
//   mutex      a binary lock with an OWNER: only the owner may unlock it,
//              relocking it is refused (EDEADLK), and if the owner exits while
//              holding it the shell releases it and tells the next owner
//              (MKF_OWNER_DIED) - a "robust" mutex.
//
// Because mutexes have owners the shell can see deadlocks: a process that
// waits for a mutex held by a process that waits for a mutex ... held by the
// first one is a cycle in the wait-for graph.  The shell reports every cycle;
// with `sem config --deadlock fail` it also refuses the request that would
// close the cycle (EDEADLK), so the process can back off.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

struct SyncWaiter {
  pid_t pid = 0;
  long since_ms = 0;
  long since_us = 0;            // for the wait-time statistics
};

struct SyncObj {
  std::string name;
  int kind = 1;                 // MK_SEMAPHORE or MK_MUTEX
  long value = 0;               // semaphore count; mutex: 1 = free, 0 = locked
  pid_t owner = 0;              // mutex holder (0 = none)
  std::deque<SyncWaiter> waiters;
  // statistics
  long acquires = 0;            // successful P() / lock
  long contended = 0;           // ...of which had to wait
  long posts = 0;
  long retries = 0;             // barging: waiters woken that had to compete again
  long total_wait_us = 0;       // time spent asleep in this object's queue
  long max_wait_us = 0;
  size_t max_queue = 0;
  bool is_mutex() const;
};

class SyncManager {
 public:
  std::function<void(const char* kind, const std::string& detail)> log;
  std::function<std::string(pid_t)> label;                     // "philo 2 (pid 123)"
  std::function<void(pid_t, int status, uint32_t flags)> wake; // answer a waiter's request now
  std::function<void(const std::string& report)> deadlock;     // a cycle was found
  bool fail_on_deadlock = false;
  // true (default): V()/unlock HANDS the object to the longest waiter (FIFO,
  // no starvation, but every hand-off is a context switch: a "lock convoy").
  // false: "barging" - the object becomes free and the longest waiter is only
  // woken to try again, so the process that just released it may take it back.
  bool fifo_handoff = true;

  // Results of wait(): 0 = acquired now, 1 = the caller sleeps (it will be
  // woken through `wake`), < 0 = -errno.
  int open(pid_t pid, const std::string& name, int kind, long initial, bool reinit, std::string& why);
  int wait(pid_t pid, const std::string& name, bool try_only, long now, std::string& why);
  int post(pid_t pid, const std::string& name, long now, std::string& why);   // pid 0 = the shell
  void detach(pid_t pid, long now);        // the process exited: leave queues, release its mutexes
  bool remove(const std::string& name, std::string& why);
  void clear_all();

  const std::map<std::string, SyncObj>& objects() const { return objs_; }
  const SyncObj* find(const std::string& name) const;
  std::string waiting_on(pid_t pid) const; // name of the object it sleeps on ("" = none)
  const std::map<pid_t, std::string>& waiting() const { return waiting_; }

  // The wait-for cycle through `pid` (empty if none) and its description.
  std::vector<pid_t> cycle_from(pid_t pid) const;
  std::string describe_cycle(const std::vector<pid_t>& cyc) const;
  std::vector<std::string> all_cycles() const;   // every cycle in the graph right now

  long deadlocks_found = 0;
  std::string last_deadlock;

 private:
  void grant(SyncObj& o, long now, uint32_t extra_flags);   // hand to the head waiter
  std::string who(pid_t pid) const { return label ? label(pid) : "pid " + std::to_string((int)pid); }
  void emit(const char* kind, const std::string& d) { if (log) log(kind, d); }

  std::map<std::string, SyncObj> objs_;
  std::map<pid_t, std::string> waiting_;   // pid -> object it waits on
};
