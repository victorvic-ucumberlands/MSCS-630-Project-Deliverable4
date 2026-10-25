// kernel.hpp - the shell's "system call" server (Deliverable 3).
//
// The shell listens on a Unix-domain SOCK_SEQPACKET socket (an abstract
// address, published in $MYSHELL_KERNEL) and every process it starts inherits
// the address.  A process that uses paged memory or a semaphore connects once;
// the kernel tells the shell its pid (SO_PEERCRED).  Each request is one
// message and the process sleeps in recv() until the shell answers, so:
//
//   * a request answered at once behaves like a fast system call;
//   * a request the shell DEFERS puts the process to sleep: a semaphore wait
//     (answered when the semaphore is posted) or a page fault that needs swap
//     I/O (answered when the simulated I/O time has passed).
//
// The CPU scheduler is told about deferred requests (hint()), so a process
// that waits for the shell is marked BLOCKED at once and the CPU goes to
// someone else; when the answer is sent it becomes runnable again.  A process
// that exits simply closes its connection: the shell then frees its memory,
// removes it from every wait queue and releases the mutexes it held.
#pragma once

#include <poll.h>
#include <sys/types.h>

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "memory.hpp"
#include "mkernel.h"
#include "sync.hpp"

class Kernel {
 public:
  MemoryManager mm;
  SyncManager sync;
  bool mem_trace = false;           // print memory events as they happen
  bool sync_trace = false;          // print synchronization events as they happen
  std::function<long()> clock;      // ms since the shell started (log timestamps)
  std::function<void()> on_block_change;   // a process started or stopped waiting for the shell
  std::function<void(pid_t)> before_wake;  // about to answer a request `pid` sleeps on

  Kernel();
  bool start(std::string& err);     // create the listening socket and export its address
  void drop_inherited();            // in a forked child of the shell: close everything, forget state
  const std::string& address() const { return addr_; }

  // ---- event loop integration -----------------------------------------
  void add_pollfds(std::vector<pollfd>& v) const;
  void service(const pollfd* fds, size_t n);   // the entries add_pollfds() appended
  void tick();                                 // complete page I/O that is due, retry, stall check
  long timeout_ms() const;                     // -1 = nothing pending

  // ---- information for the scheduler and the displays -----------------
  // -1 unknown, 0 = asleep waiting for the shell, 1 = has a request queued
  // (it is "in a system call", i.e. running).
  int hint(pid_t pid) const;
  std::string wait_reason(pid_t pid) const;    // "" or e.g. "semaphore 'empty'"
  std::string label(pid_t pid) const;          // "producer 1 (pid 123)"
  struct ClientInfo {
    pid_t pid;
    std::string label;
    std::string waiting;                       // what it waits for ("" = running)
    long requests;
  };
  std::vector<ClientInfo> clients() const;
  long requests_total = 0;

 private:
  enum class Wait { None, Sync, PageIO, Retry };
  struct Client {
    int fd = -1;
    pid_t pid = 0;
    std::string label;
    Wait wait = Wait::None;
    mk_req pending{};               // request being retried
    mk_rep deferred{};              // reply held back until ready_at
    long ready_at = 0;
    std::string waiting_for;
    long wait_since = 0;
    long requests = 0;
    bool used_sync = false;
  };

  void accept_all();
  void handle(Client& c, const mk_req& q);
  void do_access(Client& c, const mk_req& q, bool first_try);
  void reply(Client& c, const mk_rep& r);
  void disconnect(pid_t pid);
  void log_mem(const char* kind, const std::string& d);
  void log_sync(const char* kind, const std::string& d);
  void check_stall(long now);
  long now() const;

  int listen_fd_ = -1;
  std::string addr_;
  std::map<pid_t, Client> clients_;
  bool stall_reported_ = false;
  long all_blocked_since_ = -1;
};
