// shell.hpp - the Shell object: read-eval loop, process creation, job control
// and the integration of the resident CPU scheduler.
#pragma once

#include <sys/resource.h>
#include <sys/types.h>
#include <termios.h>

#include <cstdio>
#include <string>
#include <vector>

#include "cpu_sched.hpp"
#include "job.hpp"
#include "kernel.hpp"
#include "parser.hpp"
#include "scheduler.hpp"

class Shell {
 public:
  using BuiltinFn = int (*)(Shell&, const std::vector<std::string>&);

  // interactive : stdin is a terminal -> prompt, job-control signals, terminal hand-off
  // echo_input  : print each script line before running it (for demo transcripts)
  Shell(bool interactive, bool echo_input);

  // Read-eval loop over the file descriptor `fd` until EOF or `exit`.
  int run(int fd);

  // `source FILE` (Deliverable 3 demos): run the commands of FILE in THIS shell,
  // one line at a time, each echoed after a prompt as if it had been typed.
  // Stops early if a foreground command is interrupted with Ctrl-C (status 130).
  int source_file(const std::string& path);
  int source_depth = 0;

  // ---- Deliverable 4: authentication ------------------------------------
  std::string login_user;            // -u USER (password from $MYSHELL_PASSWORD)
  // Read a password: echo off on a terminal; from the next input line otherwise.
  bool read_secret(const std::string& prompt, std::string& out);
  bool read_input_line(const std::string& prompt, std::string& out);
  // Ask for a password and start a session for `name` (login / su).
  bool login_as(const std::string& name, bool quiet = false);
  bool login_dialog();               // the login prompt: login: / password:, 3 attempts
  void start_session(const std::string& name, bool go_home);
  bool owns(const Job& j) const;     // may the current user control this job?
  bool logout_requested = false;

  // ---- state shared with the built-in commands -------------------------
  JobTable jobs;
  CpuScheduler cpu;            // the resident scheduler: every command the shell starts goes through it
  Scheduler scheduler;         // `sched run` experiments (built on `cpu`)
  Kernel kern;                 // Deliverable 3: paged memory and semaphores for the shell's processes
  bool live = true;            // false = the kernel schedules the jobs (Deliverable 1 behaviour)
  int default_priority = 10;   // priority given to commands started without `prio`
  bool live_trace = false;     // print scheduling decisions as they happen
  int last_status = 0;         // $? : status of the most recent command
  pid_t last_bg = 0;           // $! : process (group) id of the last background job
  bool exit_requested = false;
  int exit_code = 0;
  bool exit_warned = false;    // "there are stopped jobs" already shown once
  pid_t shell_pid = 0;

  // ---- job control used by jobs/fg/bg/kill ------------------------------
  // Resolve "%1", "1", "%%", "%+", "%-" (or empty = current job).
  Job* resolve_job(const std::string& spec, std::string& err);
  int foreground_job(Job& job);      // fg
  int background_job(Job& job);      // bg
  // Reap children whose state changed.  notify=true also announces finished or
  // stopped background jobs and removes finished ones from the table.
  void reap_children(bool notify);
  // Let events be processed (up to timeout_ms) until job `id` leaves `old_state`.
  void wait_for_change(int id, JobState old_state, int timeout_ms);
  void announce(const Job& job);     // "[1]+  Done    sleep 2"

  // ---- scheduler integration ------------------------------------------
  void schedule_tick();              // let the scheduler act now
  void set_live(bool on);            // sched live on|off
  // Route a signal from `kill` to a scheduled job (stop/continue go through
  // the scheduler; other signals are delivered so the job acts promptly).
  int signal_job(Job& job, int sig);
  void resume_job(Job& job);         // re-admit a job the user had stopped
  long now_ms() const;               // ms since the shell started (trace timestamps)

 private:
  void execute_line(const std::string& line);
  void run_command(const Command& cmd);
  void run_prio(const Command& cmd);
  void run_builtin_inline(BuiltinFn fn, const Command& cmd);
  void launch(const Command& cmd, BuiltinFn fn, int priority);
  [[noreturn]] void child_exec(const Command& cmd, BuiltinFn fn, bool scheduled);
  [[noreturn]] void run_pipeline(const Command& cmd);   // Deliverable 4: the pipeline's leader
  int wait_foreground(Job& job);
  int wait_foreground_unscheduled(Job& job);
  int finish_foreground(int id);
  void stop_for_user(Job& job, int sig);
  void update_from_status(Job& job, int status, const struct rusage& ru);
  void flush_notifications();
  void cleanup_jobs();
  void install_scheduler_hooks();
  void trace(const char* kind, const std::string& detail);

  // Wait (up to timeout_ms; -1 = no limit) for a signal or, if watch_input,
  // for input; then reap children and let the scheduler act.  Returns true if
  // input is readable.  Terminal signals received are left in pending_sigs_.
  bool pump(long timeout_ms, bool watch_input);
  bool read_line(std::string& line);

  std::string lookup_var(const std::string& name);
  std::string prompt();
  void give_terminal_to(pid_t pgid);

  bool interactive_;
  bool echo_input_;
  int tty_fd_ = -1;
  pid_t shell_pgid_ = 0;
  struct termios shell_tmodes_{};

  int sigfd_ = -1;                    // signalfd: SIGCHLD (+ Ctrl-C/Ctrl-Z/Ctrl-\ when interactive)
  std::vector<int> pending_sigs_;     // terminal signals the shell received itself
  std::vector<int> stop_announce_;    // background jobs stopped but not yet announced
  int fg_job_id_ = 0;                 // the job in the foreground (0 = none)
  long start_ms_ = 0;

  int in_fd_ = 0;                     // input: a line buffer over a file descriptor
  std::string inbuf_;
  bool in_eof_ = false;
};
