// sync.cpp - semaphores, mutexes, FIFO wait queues and deadlock detection
// (see sync.hpp).
#include "sync.hpp"

#include <algorithm>
#include <cerrno>
#include <set>

#include <time.h>

#include "mkernel.h"

bool SyncObj::is_mutex() const { return kind == MK_MUTEX; }

static long now_us() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static const char* kind_name(int k) { return k == MK_MUTEX ? "mutex" : "semaphore"; }

const SyncObj* SyncManager::find(const std::string& name) const {
  auto it = objs_.find(name);
  return it == objs_.end() ? nullptr : &it->second;
}

std::string SyncManager::waiting_on(pid_t pid) const {
  auto it = waiting_.find(pid);
  return it == waiting_.end() ? "" : it->second;
}

int SyncManager::open(pid_t pid, const std::string& name, int kind, long initial, bool reinit, std::string& why) {
  if (name.empty() || name.size() >= MK_NAME_MAX) { why = "name must be 1-31 characters"; return -EINVAL; }
  if (kind != MK_SEMAPHORE && kind != MK_MUTEX) { why = "kind must be semaphore or mutex"; return -EINVAL; }
  if (kind == MK_SEMAPHORE && (initial < 0 || initial > 1000000)) { why = "initial value must be 0..1000000"; return -EINVAL; }
  auto it = objs_.find(name);
  if (it != objs_.end()) {
    SyncObj& o = it->second;
    if (o.kind != kind) { why = "'" + name + "' already exists as a " + kind_name(o.kind); return -EEXIST; }
    if (!reinit) return 0;                       // opened by name: the existing object
    if (!o.waiters.empty()) { why = "'" + name + "' has waiting processes"; return -EBUSY; }
    if (o.is_mutex() && o.owner) { why = "mutex '" + name + "' is locked"; return -EBUSY; }
  }
  if (objs_.size() >= 256 && it == objs_.end()) { why = "too many semaphores (256)"; return -ENOSPC; }
  SyncObj& o = objs_[name];
  o = SyncObj{};
  o.name = name;
  o.kind = kind;
  o.value = kind == MK_MUTEX ? 1 : initial;
  emit("CREATE", std::string(kind_name(kind)) + " '" + name + "'" +
                     (kind == MK_MUTEX ? " (unlocked)" : " = " + std::to_string(initial)) +
                     (pid ? " by " + who(pid) : " from the prompt"));
  return 0;
}

// The wait-for graph has an edge P -> Q when P sleeps on a mutex that Q owns.
// Following the edges from `start` either ends (someone is not waiting for a
// mutex, so the chain can still make progress) or returns to `start`.
std::vector<pid_t> SyncManager::cycle_from(pid_t start) const {
  std::vector<pid_t> path{start};
  std::set<pid_t> seen{start};
  pid_t p = start;
  for (;;) {
    auto w = waiting_.find(p);
    if (w == waiting_.end()) return {};
    const SyncObj* o = find(w->second);
    if (!o || !o->is_mutex() || !o->owner) return {};
    pid_t q = o->owner;
    if (q == start) return path;
    if (seen.count(q)) return {};                // a cycle that does not pass through start
    seen.insert(q);
    path.push_back(q);
    p = q;
  }
}

std::string SyncManager::describe_cycle(const std::vector<pid_t>& cyc) const {
  std::string s;
  for (size_t i = 0; i < cyc.size(); ++i) {
    std::string m = waiting_on(cyc[i]);
    pid_t next = cyc[(i + 1) % cyc.size()];
    std::string held;
    for (const auto& [n, o] : objs_)
      if (o.is_mutex() && o.owner == cyc[i]) held += (held.empty() ? "" : ",") + n;
    s += (i ? "; " : "") + who(cyc[i]) + " holds " + (held.empty() ? "nothing" : held) + " and waits for " + m +
         " (held by " + who(next) + ")";
  }
  return s;
}

std::vector<std::string> SyncManager::all_cycles() const {
  std::vector<std::string> out;
  std::set<pid_t> done;
  for (const auto& [pid, name] : waiting_) {
    if (done.count(pid)) continue;
    std::vector<pid_t> c = cycle_from(pid);
    if (c.empty()) continue;
    for (pid_t p : c) done.insert(p);
    out.push_back(describe_cycle(c));
  }
  return out;
}

int SyncManager::wait(pid_t pid, const std::string& name, bool try_only, long now, std::string& why) {
  auto it = objs_.find(name);
  if (it == objs_.end()) { why = "no semaphore or mutex '" + name + "' (open it first)"; return -ENOENT; }
  SyncObj& o = it->second;
  if (waiting_.count(pid)) { why = "already waiting"; return -EINVAL; }
  if (o.is_mutex()) {
    if (o.owner == pid) { why = who(pid) + " already holds mutex '" + name + "'"; return -EDEADLK; }
    if (o.value == 1) {
      o.value = 0;
      o.owner = pid;
      o.acquires++;
      emit("LOCK", who(pid) + " locked mutex '" + name + "'");
      return 0;
    }
  } else if (o.value > 0) {
    o.value--;
    o.acquires++;
    emit("WAIT", who(pid) + ": P(" + name + ") succeeded, value now " + std::to_string(o.value));
    return 0;
  }
  if (try_only) return -EAGAIN;

  // It has to sleep.  Would that close a cycle of mutex waits?
  waiting_[pid] = name;
  if (o.is_mutex()) {
    std::vector<pid_t> c = cycle_from(pid);
    if (!c.empty()) {
      deadlocks_found++;
      last_deadlock = describe_cycle(c);
      if (fail_on_deadlock) {
        waiting_.erase(pid);
        why = "deadlock: " + last_deadlock;
        if (deadlock) deadlock("DEADLOCK avoided: refused " + who(pid) + "'s lock of '" + name + "' (EDEADLK), which "
                               "would close the cycle: " + last_deadlock);
        return -EDEADLK;
      }
      if (deadlock) deadlock("DEADLOCK detected (" + std::to_string(c.size()) + " processes in a cycle): " + last_deadlock);
    }
  }
  o.waiters.push_back({pid, now, now_us()});
  o.contended++;
  o.max_queue = std::max(o.max_queue, o.waiters.size());
  std::string q;
  for (const SyncWaiter& w : o.waiters) q += (q.empty() ? "" : " ") + std::to_string((int)w.pid);
  if (o.is_mutex())
    emit("BLOCK", who(pid) + " waits for mutex '" + name + "' held by " + who(o.owner) + "; queue=[" + q + "]");
  else
    emit("BLOCK", who(pid) + ": P(" + name + ") with value 0 -> sleeps; queue=[" + q + "]");
  return 1;
}

void SyncManager::grant(SyncObj& o, long now, uint32_t extra) {
  SyncWaiter w = o.waiters.front();
  o.waiters.pop_front();
  waiting_.erase(w.pid);
  if (!fifo_handoff) {                           // barging: free it, wake the waiter to retry
    long us = std::max(0L, now_us() - w.since_us);
    o.total_wait_us += us;
    o.max_wait_us = std::max(o.max_wait_us, us);
    o.retries++;
    if (o.is_mutex()) { o.owner = 0; o.value = 1; }
    else o.value++;
    if (wake) wake(w.pid, MK_RETRY, extra);
    emit("WAKE", who(w.pid) + " woken to compete for '" + o.name + "' again (barging; the object is free)");
    return;
  }
  long waited = std::max(0L, now - w.since_ms);
  long us = std::max(0L, now_us() - w.since_us);
  o.total_wait_us += us;
  o.max_wait_us = std::max(o.max_wait_us, us);
  o.acquires++;
  if (o.is_mutex()) o.owner = w.pid;
  if (wake) wake(w.pid, 0, MKF_WAITED | extra);
  emit("WAKE", who(w.pid) + (o.is_mutex() ? " now owns mutex '" : " passes P('") + o.name + (o.is_mutex() ? "'" : "')") +
                   " after waiting " + std::to_string(waited) + " ms (first in the FIFO queue)");
}

int SyncManager::post(pid_t pid, const std::string& name, long now, std::string& why) {
  auto it = objs_.find(name);
  if (it == objs_.end()) { why = "no semaphore or mutex '" + name + "'"; return -ENOENT; }
  SyncObj& o = it->second;
  o.posts++;
  if (o.is_mutex()) {
    if (o.owner != pid) {
      o.posts--;
      why = "mutex '" + name + "' is " + (o.owner ? "held by " + who(o.owner) : std::string("not locked")) +
            "; only its owner may unlock it";
      return -EPERM;
    }
    emit("UNLOCK", who(pid) + " unlocked mutex '" + name + "'");
    if (!o.waiters.empty()) { grant(o, now, 0); return 0; }
    o.owner = 0;
    o.value = 1;
    return 0;
  }
  if (!o.waiters.empty()) {
    emit("POST", (pid ? who(pid) : std::string("the shell")) + ": V(" + name + ") with " +
                     std::to_string(o.waiters.size()) + " waiter(s): handed to the first");
    grant(o, now, 0);
    return 0;
  }
  if (o.value >= 1000000000L) { o.posts--; why = "semaphore value limit reached"; return -EOVERFLOW; }
  o.value++;
  emit("POST", (pid ? who(pid) : std::string("the shell")) + ": V(" + name + "), value now " + std::to_string(o.value));
  return 0;
}

void SyncManager::detach(pid_t pid, long now) {
  auto w = waiting_.find(pid);
  if (w != waiting_.end()) {                     // it died while asleep: leave the queue
    auto it = objs_.find(w->second);
    if (it != objs_.end()) {
      auto& q = it->second.waiters;
      q.erase(std::remove_if(q.begin(), q.end(), [&](const SyncWaiter& x) { return x.pid == pid; }), q.end());
      emit("LEAVE", who(pid) + " exited while waiting for '" + w->second + "'; removed from its queue");
    }
    waiting_.erase(w);
  }
  for (auto& [name, o] : objs_) {                // robust mutexes: release what it held
    if (!o.is_mutex() || o.owner != pid) continue;
    emit("ROBUST", who(pid) + " exited holding mutex '" + name + "'; the shell releases it");
    if (!o.waiters.empty()) grant(o, now, MKF_OWNER_DIED);
    else { o.owner = 0; o.value = 1; }
  }
}

bool SyncManager::remove(const std::string& name, std::string& why) {
  auto it = objs_.find(name);
  if (it == objs_.end()) { why = "no semaphore or mutex '" + name + "'"; return false; }
  if (!it->second.waiters.empty()) { why = "'" + name + "' has waiting processes"; return false; }
  if (it->second.is_mutex() && it->second.owner) { why = "mutex '" + name + "' is locked"; return false; }
  objs_.erase(it);
  return true;
}

void SyncManager::clear_all() {
  objs_.clear();
  waiting_.clear();
  deadlocks_found = 0;
  last_deadlock.clear();
}
