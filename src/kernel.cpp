// kernel.cpp - the shell's system-call server (see kernel.hpp).
#include "kernel.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static long mono_now_ms() {
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static constexpr size_t kMaxClients = 256;
static constexpr long kStallMs = 1000;           // everyone asleep this long = report a stall

Kernel::Kernel() {
  mm.log = [this](const char* k, const std::string& d) { log_mem(k, d); };
  sync.log = [this](const char* k, const std::string& d) { log_sync(k, d); };
  sync.label = [this](pid_t p) { return label(p); };
  sync.wake = [this](pid_t pid, int status, uint32_t flags) {
    auto it = clients_.find(pid);
    if (it == clients_.end()) return;
    Client& c = it->second;
    mk_rep r{};
    r.status = status;
    r.flags = flags;
    c.wait = Wait::None;
    c.waiting_for.clear();
    if (before_wake && c.fd >= 0) before_wake(pid);
    reply(c, r);
    if (on_block_change) on_block_change();
  };
  sync.deadlock = [this](const std::string& report) {
    fprintf(stderr, "myshell: %s\n", report.c_str());
    fflush(stderr);
  };
}

long Kernel::now() const { return clock ? clock() : mono_now_ms(); }

void Kernel::log_mem(const char* kind, const std::string& d) {
  if (!mem_trace) return;
  fprintf(stderr, "[mem  %6ld ms] %-6s %s\n", now(), kind, d.c_str());
  fflush(stderr);
}

void Kernel::log_sync(const char* kind, const std::string& d) {
  if (!sync_trace) return;
  fprintf(stderr, "[sync %6ld ms] %-6s %s\n", now(), kind, d.c_str());
  fflush(stderr);
}

bool Kernel::start(std::string& err) {
  if (listen_fd_ >= 0) return true;
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) { err = strerror(errno); return false; }
  static int counter = 0;
  std::string name = "myshell-kernel-" + std::to_string((int)getpid()) + "-" + std::to_string(++counter);
  sockaddr_un sa{};
  sa.sun_family = AF_UNIX;
  memcpy(sa.sun_path + 1, name.data(), name.size());      // abstract namespace: sun_path[0] = '\0'
  socklen_t len = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name.size());
  if (bind(fd, (sockaddr*)&sa, len) < 0 || listen(fd, 64) < 0) {
    err = strerror(errno);
    close(fd);
    return false;
  }
  listen_fd_ = fd;
  addr_ = "@" + name;
  setenv(MK_ENV, addr_.c_str(), 1);
  return true;
}

void Kernel::drop_inherited() {
  if (listen_fd_ >= 0) close(listen_fd_);
  listen_fd_ = -1;
  for (auto& [pid, c] : clients_) close(c.fd);
  clients_.clear();
  mm.clear_all();
  sync.clear_all();
  // MYSHELL_KERNEL stays in the environment: a program this child execs must
  // reach the real shell, which is still running.
}

// ---------------------------------------------------------------------------
// Event loop integration
// ---------------------------------------------------------------------------
void Kernel::add_pollfds(std::vector<pollfd>& v) const {
  if (listen_fd_ < 0) return;
  v.push_back({listen_fd_, POLLIN, 0});
  for (const auto& [pid, c] : clients_) v.push_back({c.fd, POLLIN, 0});
}

void Kernel::service(const pollfd* fds, size_t n) {
  if (listen_fd_ < 0 || n == 0) return;
  std::vector<pid_t> ready;
  for (size_t i = 1; i < n; ++i)
    if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
      for (const auto& [pid, c] : clients_)
        if (c.fd == fds[i].fd) ready.push_back(pid);
  for (pid_t pid : ready) {
    for (int burst = 0; burst < 64; ++burst) {       // a few requests per wake-up, fairly
      auto it = clients_.find(pid);
      if (it == clients_.end()) break;
      Client& c = it->second;
      mk_req q{};
      ssize_t k = recv(c.fd, &q, sizeof q, MSG_DONTWAIT);
      if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
      if (k <= 0) { disconnect(pid); break; }          // it exited (or closed the connection)
      if (k != (ssize_t)sizeof q || c.wait != Wait::None) {
        fprintf(stderr, "myshell: kernel: malformed request from %s; connection closed\n", label(pid).c_str());
        disconnect(pid);
        break;
      }
      c.requests++;
      requests_total++;
      handle(c, q);
      if (clients_.count(pid) && clients_[pid].wait != Wait::None) break;
    }
  }
  if (fds[0].revents & POLLIN) accept_all();
}

void Kernel::accept_all() {
  for (;;) {
    int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    ucred cr{};
    socklen_t len = sizeof cr;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0 || cr.pid <= 0 || clients_.count(cr.pid) ||
        clients_.size() >= kMaxClients) {
      close(fd);                                     // one connection per process
      continue;
    }
    Client& c = clients_[cr.pid];
    c.fd = fd;
    c.pid = cr.pid;
    char path[64], comm[64] = "?";
    snprintf(path, sizeof path, "/proc/%d/comm", (int)cr.pid);
    if (FILE* f = fopen(path, "r")) {
      if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0;
      fclose(f);
    }
    c.label = comm;
  }
}

void Kernel::reply(Client& c, const mk_rep& r) {
  if (c.fd < 0) return;
  // The process is asleep in recv() (or about to be); a full socket buffer
  // cannot happen because every request gets exactly one reply.
  if (send(c.fd, &r, sizeof r, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) { /* it is exiting; EOF follows */ }
}

void Kernel::disconnect(pid_t pid) {
  auto it = clients_.find(pid);
  if (it == clients_.end()) return;
  close(it->second.fd);
  it->second.fd = -1;
  it->second.wait = Wait::Sync;                    // no reply can reach it any more
  long t = now();
  sync.detach(pid, t);                             // (its label is still known for the log)
  mm.detach(pid, t);
  clients_.erase(pid);
  if (on_block_change) on_block_change();
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
static std::string name_of(const mk_req& q) {
  char buf[MK_NAME_MAX + 1];
  memcpy(buf, q.name, MK_NAME_MAX);
  buf[MK_NAME_MAX] = 0;
  return buf;
}

void Kernel::handle(Client& c, const mk_req& q) {
  mk_rep r{};
  r.frame = -1;
  std::string why;
  const std::string name = name_of(q);
  switch (q.op) {
    case MK_HELLO:
      if (!name.empty()) c.label = name;
      mm.attach(c.pid, c.label, now());
      r.a = mm.config().page_size;
      r.b = mm.config().frames;
      r.value = c.pid;
      break;
    case MK_ALLOC: {
      mm.attach(c.pid, c.label, now());
      long first = mm.alloc(c.pid, (long)q.a, why);
      if (first < 0) {
        r.status = (int)first;
        if (mem_trace || first == -ENOMEM) log_mem("REFUSE", c.label + ": allocation of " + std::to_string((long)q.a) + " page(s) refused: " + why);
      } else {
        r.value = first;
      }
      break;
    }
    case MK_FREE:
      r.status = mm.release(c.pid, (long)q.a, (long)q.b, why);
      if (r.status < 0) log_mem("REFUSE", c.label + ": free refused: " + why);
      break;
    case MK_SHM: {
      mm.attach(c.pid, c.label, now());
      long first = mm.shm_attach(c.pid, name, (long)q.a, why);
      if (first < 0) { r.status = (int)first; log_mem("REFUSE", c.label + ": " + why); }
      else r.value = first;
      break;
    }
    case MK_READ:
    case MK_WRITE:
      do_access(c, q, true);
      return;
    case MK_SEM_OPEN:
    case MK_SEM_INIT:
      c.used_sync = true;
      r.status = sync.open(c.pid, name, q.kind, (long)q.value, q.op == MK_SEM_INIT, why);
      if (r.status < 0) log_sync("REFUSE", label(c.pid) + ": " + why);
      break;
    case MK_WAIT:
    case MK_TRYWAIT: {
      c.used_sync = true;
      int s = sync.wait(c.pid, name, q.op == MK_TRYWAIT, now(), why);
      if (s == 1) {                                  // sleeps until posted
        c.wait = Wait::Sync;
        c.wait_since = now();
        const SyncObj* o = sync.find(name);
        c.waiting_for = std::string(o && o->is_mutex() ? "mutex '" : "semaphore '") + name + "'";
        if (on_block_change) on_block_change();
        return;
      }
      r.status = s;
      if (s < 0 && s != -EAGAIN && s != -EDEADLK) log_sync("REFUSE", label(c.pid) + ": " + why);
      break;
    }
    case MK_POST:
      c.used_sync = true;
      r.status = sync.post(c.pid, name, now(), why);
      if (r.status < 0) log_sync("REFUSE", label(c.pid) + ": " + why);
      break;
    case MK_INFO:
      if (const ProcMem* p = mm.proc(c.pid)) {
        r.s[MK_INFO_REFS] = p->st.refs;
        r.s[MK_INFO_FAULTS] = p->st.faults;
        r.s[MK_INFO_MAJOR] = p->st.major;
        r.s[MK_INFO_RESIDENT] = mm.resident_of(*p);
        r.s[MK_INFO_PEAK] = p->st.peak_resident;
        r.s[MK_INFO_VPAGES] = p->vpages();
        r.s[MK_INFO_EVICTED] = p->st.evictions;
      }
      break;
    default:
      r.status = -EINVAL;
  }
  reply(c, r);
}

void Kernel::do_access(Client& c, const mk_req& q, bool first_try) {
  long t = now();
  Access a = mm.access(c.pid, (int64_t)q.a, q.op == MK_WRITE, (int64_t)q.value, t);
  if (a.retry) {                                     // every frame is busy with swap I/O
    if (first_try || c.wait != Wait::Retry) {
      c.wait = Wait::Retry;
      c.pending = q;
      c.wait_since = t;
      c.waiting_for = "a free page frame";
      if (on_block_change) on_block_change();
    }
    return;
  }
  mk_rep r{};
  r.status = a.status;
  r.flags = a.flags;
  r.value = a.value;
  r.frame = a.frame;
  r.victim_pid = a.victim_pid;
  r.victim_page = a.victim_page;
  snprintf(r.victim, sizeof r.victim, "%s", a.victim_label.c_str());
  if (a.status == -EFAULT) {
    kill(c.pid, SIGSEGV);                            // what the MMU does to a bad access
    c.wait = Wait::None;
    reply(c, r);
    return;
  }
  if (a.ready_at > t) {                              // the page is being read from / written to swap
    c.wait = Wait::PageIO;
    c.deferred = r;
    c.ready_at = a.ready_at;
    c.wait_since = t;
    c.waiting_for = "page I/O (swap)";
    if (on_block_change) on_block_change();
    return;
  }
  bool was_waiting = c.wait != Wait::None;
  c.wait = Wait::None;
  c.waiting_for.clear();
  if (was_waiting && before_wake) before_wake(c.pid);
  reply(c, r);
  if (was_waiting && on_block_change) on_block_change();
}

// ---------------------------------------------------------------------------
// Timers: page I/O completion, retries, stall detection
// ---------------------------------------------------------------------------
void Kernel::tick() {
  long t = now();
  std::vector<pid_t> due, retry;
  for (auto& [pid, c] : clients_) {
    if (c.wait == Wait::PageIO && c.ready_at <= t) due.push_back(pid);
    if (c.wait == Wait::Retry) retry.push_back(pid);
  }
  for (pid_t pid : due) {
    Client& c = clients_[pid];
    c.wait = Wait::None;
    c.waiting_for.clear();
    if (before_wake) before_wake(pid);
    reply(c, c.deferred);
  }
  for (pid_t pid : retry) {
    auto it = clients_.find(pid);
    if (it != clients_.end()) do_access(it->second, it->second.pending, false);
  }
  if (!due.empty() && on_block_change) on_block_change();
  check_stall(t);
}

long Kernel::timeout_ms() const {
  long best = -1;
  long t = now();
  auto take = [&](long v) { if (v < 0) v = 0; if (best < 0 || v < best) best = v; };
  for (const auto& [pid, c] : clients_) {
    if (c.wait == Wait::PageIO) take(c.ready_at - t);
    if (c.wait == Wait::Retry) take(1);
  }
  if (all_blocked_since_ >= 0 && !stall_reported_) take(all_blocked_since_ + kStallMs - t);
  return best;
}

// A stall: at least two processes use the shell's semaphores, every one of
// them is asleep on one, and nothing has changed for a second.  Unlike a
// mutex cycle this cannot be proven (the shell could post from the prompt),
// so it is reported as a warning with what each process waits for.
void Kernel::check_stall(long t) {
  int users = 0, asleep = 0;
  for (const auto& [pid, c] : clients_) {
    if (!c.used_sync && c.wait != Wait::Sync) continue;
    ++users;
    asleep += c.wait == Wait::Sync;
  }
  if (users < 2 || asleep < users) {
    all_blocked_since_ = -1;
    stall_reported_ = false;
    return;
  }
  if (all_blocked_since_ < 0) all_blocked_since_ = t;
  if (stall_reported_ || t - all_blocked_since_ < kStallMs) return;
  stall_reported_ = true;
  std::vector<std::string> cycles = sync.all_cycles();
  std::string what;
  for (const auto& [pid, c] : clients_)
    if (c.wait == Wait::Sync) what += (what.empty() ? "" : "; ") + label(pid) + " waits for " + c.waiting_for;
  fprintf(stderr, "myshell: STALL: all %d processes using semaphores have been asleep for %ld ms - %s%s\n", users,
          kStallMs, what.c_str(),
          cycles.empty() ? " (no mutex cycle: a semaphore that nobody will post?)" : " (a mutex cycle: deadlock)");
  fflush(stderr);
}

// ---------------------------------------------------------------------------
// Information
// ---------------------------------------------------------------------------
int Kernel::hint(pid_t pid) const {
  auto it = clients_.find(pid);
  if (it == clients_.end()) return -1;
  if (it->second.wait != Wait::None) return 0;
  pollfd p{it->second.fd, POLLIN, 0};
  if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) return 1;   // a request is waiting for the shell
  return -1;
}

std::string Kernel::wait_reason(pid_t pid) const {
  auto it = clients_.find(pid);
  if (it == clients_.end() || it->second.wait == Wait::None) return "";
  return it->second.waiting_for;
}

std::string Kernel::label(pid_t pid) const {
  auto it = clients_.find(pid);
  std::string l = it != clients_.end() ? it->second.label : "";
  if (l.empty()) return "pid " + std::to_string((int)pid);
  return l + " (pid " + std::to_string((int)pid) + ")";
}

std::vector<Kernel::ClientInfo> Kernel::clients() const {
  std::vector<ClientInfo> v;
  for (const auto& [pid, c] : clients_) v.push_back({pid, c.label, c.waiting_for, c.requests});
  return v;
}
