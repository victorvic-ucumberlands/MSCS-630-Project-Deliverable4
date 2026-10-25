// job.cpp - implementation of JobTable and Job helpers.
#include "job.hpp"

#include <algorithm>

const char* to_string(JobState s) {
  switch (s) {
    case JobState::New:        return "New";
    case JobState::Ready:      return "Ready";
    case JobState::Running:    return "Running";
    case JobState::Stopped:    return "Stopped";
    case JobState::Done:       return "Done";
    case JobState::Terminated: return "Terminated";
  }
  return "?";
}

static long ms_between(Job::Clock::time_point a, Job::Clock::time_point b) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
}

long Job::turnaround_ms() const { return finished() ? ms_between(arrival, finish) : 0; }
long Job::response_ms() const { return ms_between(arrival, first_run); }
// Waiting time = time spent ready to run but not holding the CPU.  For a
// scheduler-managed process the shell measured that directly (ready_ms): it
// excludes both the time the process held the CPU and the time it was blocked
// in the kernel.  For a job the kernel scheduled freely (live scheduling off)
// the consumed CPU time is the best available approximation.
long Job::wait_ms() const {
  if (scheduled || dispatches > 0) return ready_ms;
  long w = turnaround_ms() - (cpu_user_ms + cpu_sys_ms);
  return w < 0 ? 0 : w;  // clock granularity can make this slightly negative
}

Job& JobTable::add(pid_t pid, pid_t pgid, const std::string& command, bool foreground) {
  Job j;
  // Job numbers behave like bash: the lowest number not used by an active job,
  // so a session of short jobs keeps seeing [1], [2] ... instead of growing forever.
  int n = 1;
  while (find_by_id(n)) ++n;
  j.id = n;
  j.serial = next_serial_++;
  j.pid = pid;
  j.pgid = pgid;
  j.command = command;
  j.state = JobState::Running;  // Deliverable 1 starts every job immediately
  j.foreground = foreground;
  j.arrival = j.first_run = Job::Clock::now();
  j.submitted_wall = std::time(nullptr);
  j.use_seq = ++seq_;
  active_.push_back(j);
  return active_.back();
}

Job* JobTable::find_by_id(int id) {
  for (auto& j : active_) if (j.id == id) return &j;
  return nullptr;
}

Job* JobTable::find_by_pid(pid_t pid) {
  for (auto& j : active_) if (j.pid == pid) return &j;
  return nullptr;
}

std::vector<Job*> JobTable::by_recency() {
  std::vector<Job*> v;
  for (auto& j : active_) v.push_back(&j);
  std::sort(v.begin(), v.end(), [](const Job* a, const Job* b) {
    bool as = a->state == JobState::Stopped, bs = b->state == JobState::Stopped;
    if (as != bs) return as;                 // stopped jobs first
    return a->use_seq > b->use_seq;          // then most recently used
  });
  return v;
}

Job* JobTable::current() {
  auto v = by_recency();
  return v.empty() ? nullptr : v[0];
}

Job* JobTable::previous() {
  auto v = by_recency();
  return v.size() < 2 ? nullptr : v[1];
}

std::vector<Job*> JobTable::active() {
  std::vector<Job*> v;
  for (auto& j : active_) v.push_back(&j);  // list is already in id order
  return v;
}

bool JobTable::has_stopped() const {
  for (const auto& j : active_) if (j.state == JobState::Stopped) return true;
  return false;
}

void JobTable::retire(int id) {
  for (auto it = active_.begin(); it != active_.end(); ++it) {
    if (it->id == id) {
      history_.push_back(*it);
      active_.erase(it);
      return;
    }
  }
}
