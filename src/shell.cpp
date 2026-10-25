// shell.cpp - read-eval loop, process creation, job control, and the
// integration of the resident CPU scheduler.
//
// Process model
// -------------
//  * Every external command runs in its own child created with fork() and
//    replaced with execvp().  The child is placed in its own process group
//    (pgid == pid) so signals aimed at a job never hit the shell or other jobs.
//  * Every such command is SCHEDULED BY THE SHELL (Deliverable 2).  The child
//    stops itself just before exec; the shell admits it to the resident
//    CpuScheduler with the default priority (or the one given with `prio`) and
//    from then on only the scheduler continues (SIGCONT) or stops (SIGSTOP) it.
//    `sched live off` returns to the Deliverable 1 behaviour, in which the
//    kernel schedules the jobs freely.
//  * The shell never blocks indefinitely: at the prompt and while waiting for a
//    foreground job it sleeps in poll() on a signalfd (SIGCHLD and the
//    terminal signals) and on its input, with the scheduler's timeout.  So the
//    time slice is enforced, blocked processes are noticed and finished jobs
//    are reaped while the user is typing.
//  * Terminal ownership follows the CPU.  A foreground job owns the terminal
//    while it is continued (running, or blocked e.g. waiting for keyboard
//    input).  While the scheduler has it stopped in the ready queue the shell
//    holds the terminal, so Ctrl-C and Ctrl-Z reach the shell, which applies
//    them to the job through the scheduler.
//  * Built-ins that change shell state (cd, exit, fg, bg, jobs, kill, sched)
//    run in the shell process itself - the shell's equivalent of system calls
//    executed by the kernel - and are not scheduled.  A built-in run with '&'
//    is forked and scheduled like any other command.
#include "shell.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "builtins.hpp"
#include "security.hpp"

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Open the target of a redirection.  Prints a diagnostic and returns -1 on error.
// Deliverable 4: the shell checks the user's permission first (read for <,
// write - or create in the directory - for > and >>) and records a file it
// creates as owned by the user.
// May the current user make this redirection?  (prints the denial)
static bool authorize_redirect(const Redirect& r) {
  Security& sec = Security::get();
  struct stat st;
  bool exists = stat(r.path.c_str(), &st) == 0;
  if (r.kind == Redirect::Kind::In) return sec.allow(sec.check(r.path, kRead, "reading (<)"), "myshell", r.path);
  return sec.allow(exists ? sec.check(r.path, kWrite, r.kind == Redirect::Kind::Out ? "writing (>)" : "appending (>>)")
                          : sec.check_create(r.path, "creating (>)"),
                   "myshell", r.path);
}

static int open_redirect(const Redirect& r) {
  int flags = 0;
  Security& sec = Security::get();
  struct stat st;
  bool exists = stat(r.path.c_str(), &st) == 0;
  if (!authorize_redirect(r)) return -1;
  switch (r.kind) {
    case Redirect::Kind::In:
      flags = O_RDONLY;
      break;
    case Redirect::Kind::Out:
    case Redirect::Kind::Append:
      flags = O_WRONLY | O_CREAT | (r.kind == Redirect::Kind::Out ? O_TRUNC : O_APPEND);
      break;
  }
  int fd = open(r.path.c_str(), flags, 0644);
  if (fd < 0) fprintf(stderr, "myshell: %s: %s\n", r.path.c_str(), strerror(errno));
  else if (!exists && flags != O_RDONLY) sec.record_new(r.path, false);
  return fd;
}

// Programs that modify the files they are given (their file arguments need
// write permission, not just read).
static bool modifies_its_files(const std::string& prog) {
  static const char* w[] = {"tee", "truncate", "dd", "ln", "shred", "unlink", "install", "chmod", "chown", "chgrp",
                            "sed", "cp", "mv", "rm", "touch", "mkdir", "rmdir", "rsync", nullptr};
  std::string base = prog.substr(prog.rfind('/') + 1);
  for (int i = 0; w[i]; ++i)
    if (base == w[i]) return true;
  return false;
}

// Before an external program runs: the program file needs execute permission
// (and read, for a script), and every existing file it is given needs read
// (or write, for a program that modifies its files) - all decided by the
// shell's permission model inside the managed tree.
static bool authorize_program(const Command& c) {
  Security& sec = Security::get();
  const std::string& prog = c.argv[0];
  std::string path;
  if (prog.find('/') != std::string::npos) {
    path = prog;
  } else {                                         // a program found on $PATH
    const char* p = getenv("PATH");
    std::string dirs = p ? p : "/usr/bin:/bin";
    size_t i = 0;
    while (i <= dirs.size()) {
      size_t j = dirs.find(':', i);
      std::string d = dirs.substr(i, j == std::string::npos ? std::string::npos : j - i);
      std::string cand = (d.empty() ? "." : d) + "/" + prog;
      if (access(cand.c_str(), X_OK) == 0) { path = cand; break; }
      if (j == std::string::npos) break;
      i = j + 1;
    }
  }
  if (!path.empty()) {
    std::string abs = sec.canon(path);
    if (sec.managed(abs) || sec.in_db(abs)) {
      int need = kExec;
      if (FILE* f = fopen(abs.c_str(), "r")) {      // a script must also be readable
        char b[2] = {0, 0};
        if (fread(b, 1, 2, f) == 2 && b[0] == '#' && b[1] == '!') need |= kRead;
        fclose(f);
      }
      if (!sec.allow(sec.check(abs, need, need & kRead ? "running a script" : "running a program"), "myshell", path))
        return false;
    }
  }
  bool writer = modifies_its_files(prog);
  std::string base = prog.substr(prog.rfind('/') + 1);
  // ln: a link grants nothing (the target is checked whenever the link is
  // used), so only the place where the link is created is checked
  size_t last = c.argv.size() - 1;
  if (base == "ln") {
    while (last >= 1 && c.argv[last][0] == '-') --last;
    if (last < 1) return true;
  }
  for (size_t i = (base == "ln" ? last : 1); i < c.argv.size(); ++i) {
    const std::string& a = c.argv[i];
    if (a.empty() || a[0] == '-') continue;
    struct stat st;
    if (stat(a.c_str(), &st) < 0) {
      // a file that a writer program would create: the directory must allow it
      if (writer && (base == "ln" || i == last) &&
          !sec.allow(sec.check_create(a, "creating it"), prog.c_str(), a))
        return false;
      continue;
    }
    std::string abs = sec.canon(a);
    if (!sec.managed(abs) && !sec.in_db(abs) && !writer) continue;
    int need = S_ISDIR(st.st_mode) ? (kRead | kExec) : kRead;
    if (writer) need |= kWrite;
    if (!sec.allow(sec.check(abs, need, writer ? "modifying it" : "reading it"), prog.c_str(), a)) return false;
  }
  return true;
}

static long tv_ms(const struct timeval& tv) { return tv.tv_sec * 1000L + tv.tv_usec / 1000L; }

static bool is_stop_signal(int s) { return s == SIGSTOP || s == SIGTSTP || s == SIGTTIN || s == SIGTTOU; }

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
Shell::Shell(bool interactive, bool echo_input)
    : interactive_(interactive), echo_input_(echo_input) {
  shell_pid = getpid();
  shell_pgid_ = getpgrp();
  {
    std::string err = Security::get().init();
    if (!err.empty()) fprintf(stderr, "myshell: security: %s\n", err.c_str());
  }
  start_ms_ = proc::mono_ms();
  signal(SIGPIPE, SIG_IGN);  // a closed pipe must not kill the shell; write() gets EPIPE instead

  // A fresh shell has no "previous directory": drop an inherited OLDPWD so
  // `cd -` cannot jump to a directory belonging to the parent shell.
  unsetenv("OLDPWD");
  char cwd[4096];
  if (getcwd(cwd, sizeof cwd)) setenv("PWD", cwd, 1);

  if (interactive_) {
    tty_fd_ = STDIN_FILENO;
    // If we were started in the background, wait until we own the terminal.
    while (true) {
      pid_t fg = tcgetpgrp(tty_fd_);
      if (fg < 0 || fg == (shell_pgid_ = getpgrp())) break;
      kill(-shell_pgid_, SIGTTIN);
    }
    // The shell itself must survive Ctrl-C / Ctrl-Z / Ctrl-\ and must be
    // allowed to call tcsetpgrp() from a background process group.
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    if (setpgid(shell_pid, shell_pid) == 0) shell_pgid_ = shell_pid;
    else shell_pgid_ = getpgrp();
    tcsetpgrp(tty_fd_, shell_pgid_);
    tcgetattr(tty_fd_, &shell_tmodes_);
  }

  // Signals the shell waits for are blocked and read from a signalfd, so
  // they can be waited for together with input in one poll().  Blocked
  // signals are queued even when their disposition is "ignore", which is how
  // the interactive shell still learns about a Ctrl-C it received itself.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  if (interactive_) {
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTSTP);
  }
  sigprocmask(SIG_BLOCK, &set, nullptr);
  sigfd_ = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);

  install_scheduler_hooks();

  // Deliverable 3: the system-call server for paged memory and semaphores.
  kern.clock = [this] { return now_ms(); };
  kern.on_block_change = [this] { cpu.reprobe(); };
  kern.before_wake = [this](pid_t p) { cpu.wake(p); };
  kern.sync.user_of = [this](pid_t p) -> std::string {     // the user a process works for
    if (p > 0) {
      pid_t g = getpgid(p);
      for (Job* j : jobs.active())
        if (j->pgid == g) return j->owner;
    }
    return Security::get().user();
  };
  cpu.pid_hint = [this](pid_t p) { return kern.hint(p); };
  cpu.wait_reason = [this](pid_t p) { return kern.wait_reason(p); };
  std::string err;
  if (!kern.start(err))
    fprintf(stderr, "myshell: warning: memory/synchronization server unavailable: %s\n", err.c_str());
}

long Shell::now_ms() const { return proc::mono_ms() - start_ms_; }

void Shell::give_terminal_to(pid_t pgid) {
  if (interactive_) tcsetpgrp(tty_fd_, pgid);
}

void Shell::trace(const char* kind, const std::string& detail) {
  if (!live_trace) return;
  fprintf(stderr, "[sched %6ld ms] %-8s %s  ready=%s\n", now_ms(), kind, detail.c_str(), cpu.ready_text().c_str());
  fflush(stderr);
}

// Connect the scheduler to the shell: event trace, terminal ownership for the
// foreground job, and job records for processes the scheduler reaped itself.
void Shell::install_scheduler_hooks() {
  cpu.log = [this](const char* kind, const std::string& d) { trace(kind, d); };
  cpu.before_continue = [this](Job& j) {
    if (interactive_ && fg_job_id_ && j.id == fg_job_id_ && jobs.find_by_id(j.id) == &j) give_terminal_to(j.pgid);
  };
  cpu.after_stop = [this](Job& j) {
    if (interactive_ && fg_job_id_ && j.id == fg_job_id_ && jobs.find_by_id(j.id) == &j) give_terminal_to(shell_pgid_);
  };
  cpu.collected = [this](Job& j, int st, const struct rusage& ru) { update_from_status(j, st, ru); };
  cpu.user_stopped = [this](Job& j, int sig) {
    j.state = JobState::Stopped;
    j.stop_signal = sig;
    j.stop_count++;
    jobs.touch(j);
    if (j.id != fg_job_id_) stop_announce_.push_back(j.id);
  };
}

std::string Shell::lookup_var(const std::string& name) {
  if (name == "?") return std::to_string(last_status);
  if (name == "$") return std::to_string(shell_pid);
  if (name == "!") return last_bg ? std::to_string(last_bg) : "";
  const char* v = getenv(name.c_str());
  return v ? v : "";
}

std::string Shell::prompt() {
  char buf[4096];
  std::string cwd = getcwd(buf, sizeof buf) ? buf : "?";
  const char* home = getenv("HOME");
  if (home && *home && cwd.compare(0, strlen(home), home) == 0 &&
      (cwd.size() == strlen(home) || cwd[strlen(home)] == '/'))
    cwd = "~" + cwd.substr(strlen(home));
  Security& sec = Security::get();
  if (cwd[0] == '/' && sec.managed(cwd)) cwd = sec.rel(cwd);   // inside the managed tree: fs/...
  return (sec.logged_in() ? sec.user() + "@" : std::string()) + "myshell:" + cwd + (sec.is_admin() ? "# " : "$ ");
}

// ---------------------------------------------------------------------------
// Authentication (Deliverable 4)
// ---------------------------------------------------------------------------
bool Shell::read_input_line(const std::string& prompt_text, std::string& out) {
  fputs(prompt_text.c_str(), stdout);
  fflush(stdout);
  if (!read_line(out)) return false;
  while (!out.empty() && out.back() == '\r') out.pop_back();
  return true;
}

bool Shell::read_secret(const std::string& prompt_text, std::string& out) {
  // Echo goes off BEFORE the prompt appears, so nothing typed after it is shown.
  struct termios t{}, quiet{};
  bool tty = isatty(in_fd_) && tcgetattr(in_fd_, &t) == 0;
  if (tty) {
    quiet = t;
    quiet.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
    tcsetattr(in_fd_, TCSANOW, &quiet);
  }
  fputs(prompt_text.c_str(), stdout);
  fflush(stdout);
  bool ok = read_line(out);
  if (tty) {
    tcsetattr(in_fd_, TCSANOW, &t);
    fputc('\n', stdout);
  } else {
    fputs("********\n", stdout);                 // read from a script: never shown
  }
  fflush(stdout);
  while (!out.empty() && out.back() == '\r') out.pop_back();
  return ok;
}

void Shell::start_session(const std::string& name, bool go_home) {
  Security& sec = Security::get();
  sec.begin_session(name);
  std::string home = sec.home_of(name);
  struct stat st;
  if (stat(home.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
    setenv("HOME", home.c_str(), 1);
    if (go_home && chdir(home.c_str()) == 0) setenv("PWD", home.c_str(), 1);
  }
  setenv("USER", name.c_str(), 1);
  setenv("LOGNAME", name.c_str(), 1);
}

bool Shell::login_as(const std::string& name, bool quiet) {
  Security& sec = Security::get();
  std::string pw;
  if (!read_secret("password: ", pw)) return false;
  Security::Auth a = sec.authenticate(name, pw);
  std::fill(pw.begin(), pw.end(), '\0');
  if (a == Security::Auth::Ok) {
    start_session(name, true);
    if (!quiet) {
      const User* u = sec.current();
      char when[64] = "never";
      if (sec.previous_login) {
        time_t t = (time_t)sec.previous_login;
        struct tm tmv;
        localtime_r(&t, &tmv);
        strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tmv);
      }
      printf("Welcome, %s (role %s, group %s). Last login: %s.\n", name.c_str(), to_string(u->role),
             group_of(u->role).c_str(), when);
      if (sec.failures_before_login)
        printf("Warning: %d failed login attempt(s) since your last login.\n", sec.failures_before_login);
      fflush(stdout);
    }
    return true;
  }
  proc::sleep_ms(1000);                               // slow down guessing
  if (a == Security::Auth::Locked) fprintf(stderr, "login: account '%s' is locked; ask an administrator\n", name.c_str());
  else fprintf(stderr, "login: Login incorrect\n");
  return false;
}

bool Shell::login_dialog() {
  Security& sec = Security::get();
  printf("myshell - please log in (users: %zu)\n", sec.users().size());
  for (int attempt = 1; attempt <= 3; ++attempt) {
    std::string name;
    if (!read_input_line("login: ", name)) return false;
    if (name.empty()) { --attempt; continue; }
    if (login_as(name)) return true;
  }
  fprintf(stderr, "login: too many failed attempts\n");
  return false;
}

bool Shell::owns(const Job& j) const {
  Security& sec = Security::get();
  return sec.is_admin() || j.owner.empty() || j.owner == sec.user();
}

// ---------------------------------------------------------------------------
// The event pump: the only place the shell sleeps
// ---------------------------------------------------------------------------
bool Shell::pump(long timeout_ms, bool watch_input) {
  std::vector<pollfd> fds;
  fds.push_back({sigfd_, POLLIN, 0});
  if (watch_input) fds.push_back({in_fd_, POLLIN, 0});
  const size_t k0 = fds.size();
  kern.add_pollfds(fds);                       // the system-call server's sockets
  long kt = kern.timeout_ms();                 // page I/O that completes, ...
  if (kt >= 0 && (timeout_ms < 0 || kt < timeout_ms)) timeout_ms = kt;
  int r = poll(fds.data(), fds.size(), (int)std::min<long>(timeout_ms, 1000000));
  bool input = false;
  if (r > 0) {
    if (fds[0].revents & POLLIN) {
      signalfd_siginfo si;
      while (read(sigfd_, &si, sizeof si) == (ssize_t)sizeof si)
        if (si.ssi_signo != SIGCHLD) pending_sigs_.push_back((int)si.ssi_signo);
    }
    if (watch_input && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) input = true;
    kern.service(fds.data() + k0, fds.size() - k0);
  }
  kern.tick();
  reap_children(false);
  schedule_tick();
  return input;
}

void Shell::schedule_tick() {
  if (live) cpu.tick();
}

// Read one line from in_fd_, keeping the scheduler and the reaper running
// while waiting for it.
bool Shell::read_line(std::string& line) {
  for (;;) {
    size_t nl = inbuf_.find('\n');
    if (nl != std::string::npos) {
      line = inbuf_.substr(0, nl);
      inbuf_.erase(0, nl + 1);
      return true;
    }
    if (in_eof_) {
      if (inbuf_.empty()) return false;
      line.swap(inbuf_);
      inbuf_.clear();
      return true;
    }
    pending_sigs_.clear();
    bool ready = pump(cpu.timeout_ms(), true);
    for (int s : pending_sigs_) {
      if (s == SIGINT && interactive_) {                // Ctrl-C at the prompt: a fresh prompt
        fputc('\n', stdout);
        reap_children(true);
        fputs(prompt().c_str(), stdout);
        fflush(stdout);
      }                                                 // Ctrl-Z / Ctrl-\ at the prompt: ignored
    }
    pending_sigs_.clear();
    if (ready) {
      char buf[8192];
      ssize_t k = read(in_fd_, buf, sizeof buf);
      if (k > 0) inbuf_.append(buf, (size_t)k);
      else if (k == 0) in_eof_ = true;
      else if (errno != EINTR && errno != EAGAIN) in_eof_ = true;
    }
  }
}

// ---------------------------------------------------------------------------
// Read-eval loop
// ---------------------------------------------------------------------------
int Shell::run(int fd) {
  in_fd_ = fd;
  Security& sec = Security::get();
  if (!sec.have_users()) {
    fprintf(stderr, "myshell: no users are defined yet; run './myshell --setup-demo' first\n");
    return 1;
  }
  if (!login_user.empty()) {                    // -u USER: password from the environment
    const char* pw = getenv("MYSHELL_PASSWORD");
    if (!pw || sec.authenticate(login_user, pw) != Security::Auth::Ok) {
      fprintf(stderr, "myshell: authentication failed for '%s'\n", login_user.c_str());
      return 1;
    }
    unsetenv("MYSHELL_PASSWORD");               // children must not inherit it
    start_session(login_user, false);
  } else if (interactive_ && !login_dialog()) {
    return 1;
  }
  while (!exit_requested) {
    if (logout_requested) {                     // logout: back to the login prompt
      logout_requested = false;
      if (interactive_) {
        fputc('\n', stdout);
        if (!login_dialog()) break;
      }
    }
    pump(0, false);              // between commands: reap and let the scheduler act
    reap_children(true);         // report finished/stopped background jobs first
    if (interactive_) {
      fputs(prompt().c_str(), stdout);
      fflush(stdout);
    }
    std::string line;
    if (!read_line(line)) {
      if (interactive_) fputs("exit\n", stdout);  // Ctrl-D
      exit_code = last_status;
      break;
    }
    while (!line.empty() && line.back() == '\r') line.pop_back();
    if (echo_input_ && !interactive_) {
      printf("myshell$ %s\n", line.c_str());
      fflush(stdout);
    }
    execute_line(line);
  }
  fflush(stdout);
  cleanup_jobs();
  return exit_code;
}

int Shell::source_file(const std::string& path) {
  if (source_depth >= 8) {
    fprintf(stderr, "source: nested too deeply (8 levels)\n");
    return 1;
  }
  FILE* f = fopen(path.c_str(), "r");
  if (!f) {
    fprintf(stderr, "source: %s: %s\n", path.c_str(), strerror(errno));
    return 1;
  }
  ++source_depth;
  char* buf = nullptr;
  size_t cap = 0;
  ssize_t n;
  int status = 0;
  while (!exit_requested && (n = getline(&buf, &cap, f)) >= 0) {
    std::string line(buf, (size_t)n);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    pump(0, false);                       // as between typed commands: reap, let the scheduler act
    reap_children(true);
    if (line.empty()) continue;
    if (line[0] == '#') {                 // a comment is shown as a caption
      printf("%s\n", line.c_str());
      fflush(stdout);
      continue;
    }
    printf("%s%s\n", prompt().c_str(), line.c_str());
    fflush(stdout);
    execute_line(line);
    status = last_status;
    if (status == 130) {                  // Ctrl-C on a foreground command: stop the script
      fprintf(stderr, "source: %s interrupted\n", path.c_str());
      break;
    }
  }
  free(buf);
  fclose(f);
  --source_depth;
  pump(0, false);
  reap_children(true);
  return status;
}

// Validate the whole line first (syntax errors run nothing), then execute
// command by command so that $? and cd take effect for later commands.
void Shell::execute_line(const std::string& line) {
  if (line.size() > Parser::kMaxLine) {
    fprintf(stderr, "myshell: input line too long (%zu bytes, limit %zu)\n", line.size(), Parser::kMaxLine);
    last_status = 2;
    return;
  }
  if (line.find('\0') != std::string::npos) {
    fprintf(stderr, "myshell: invalid input (embedded NUL byte)\n");
    last_status = 2;
    return;
  }
  Command cmd;
  {  // pass 1: syntax check with a dummy variable lookup
    Parser check(line, [](const std::string&) { return std::string("x"); });
    for (;;) {
      Parser::Status st = check.next(cmd);
      if (st == Parser::Status::End) break;
      if (st == Parser::Status::Error) {
        fprintf(stderr, "myshell: %s\n", check.error().c_str());
        last_status = 2;
        return;
      }
    }
  }
  // pass 2: real expansion + execution
  Parser p(line, [this](const std::string& n) { return lookup_var(n); });
  while (!exit_requested) {
    Parser::Status st = p.next(cmd);
    if (st == Parser::Status::End) break;
    if (st == Parser::Status::Error) {
      fprintf(stderr, "myshell: %s\n", p.error().c_str());
      last_status = 2;
      break;
    }
    run_command(cmd);
    pump(0, false);              // let the scheduler see the new job straight away
  }
}

void Shell::run_command(const Command& cmd) {
  if (cmd.argv.empty()) return;
  if (!Security::get().logged_in() && cmd.argv[0] != "login" && cmd.argv[0] != "exit" && cmd.argv[0] != "help") {
    fprintf(stderr, "myshell: not logged in (use: login USER)\n");
    last_status = 1;
    return;
  }
  if (cmd.argv[0] != "exit") exit_warned = false;
  if (cmd.argv[0] == "prio") { run_prio(cmd); return; }
  if (!cmd.pipeline.empty()) {               // a | b | c: one job, scheduled as a unit
    launch(cmd, nullptr, default_priority);
    return;
  }

  BuiltinFn fn = find_builtin(cmd.argv[0]);
  if (fn && !cmd.background)
    run_builtin_inline(fn, cmd);
  else
    launch(cmd, fn, default_priority);  // external command, or built-in with '&'
}

// `prio N COMMAND...` runs one command with priority N.
// `prio N %JOB` changes the priority of an existing job (renice).
// `prio` alone shows the default priority.
void Shell::run_prio(const Command& cmd) {
  const auto& a = cmd.argv;
  if (a.size() == 1) {
    printf("default priority %d (prio N COMMAND runs one command with priority N)\n", default_priority);
    last_status = 0;
    return;
  }
  long n = -1;
  bool ok = a[1].size() <= 2 && !a[1].empty();
  for (char c : a[1]) ok = ok && c >= '0' && c <= '9';
  if (ok) n = std::strtol(a[1].c_str(), nullptr, 10);
  if (!ok || n < 0 || n > 99) {
    fprintf(stderr, "prio: priority must be an integer from 0 to 99, got '%s'\n", a[1].c_str());
    last_status = 2;
    return;
  }
  if (a.size() < 3) {
    fprintf(stderr, "prio: usage: prio N COMMAND [ARGS...]   or   prio N %%JOB\n");
    last_status = 2;
    return;
  }
  Security& sec = Security::get();
  if (n < default_priority && !sec.is_admin()) {          // like nice(1): only root may raise priority
    Decision d;
    d.ok = false;
    d.why = "priority " + std::to_string(n) + " is more urgent than the default " + std::to_string(default_priority) +
            "; only admin may raise a priority (" + sec.user() + " is " + to_string(sec.current()->role) + ")";
    sec.allow(d, "prio", "");
    last_status = 1;
    return;
  }
  if (!a[2].empty() && a[2][0] == '%') {                  // renice an existing job
    if (a.size() > 3) { fprintf(stderr, "prio: too many arguments\n"); last_status = 2; return; }
    reap_children(false);
    std::string err;
    Job* j = resolve_job(a[2], err);
    if (!j || j->finished()) { fprintf(stderr, "prio: %s\n", j ? "job has finished" : err.c_str()); last_status = 1; return; }
    if (!owns(*j)) {
      Decision d;
      d.ok = false;
      d.why = "job [" + std::to_string(j->id) + "] belongs to " + j->owner;
      sec.allow(d, "prio", a[2]);
      last_status = 1;
      return;
    }
    if ((int)n < j->priority && !sec.is_admin()) {
      Decision d;
      d.ok = false;
      d.why = "only admin may make a job more urgent (" + std::to_string(j->priority) + " -> " + std::to_string(n) + ")";
      sec.allow(d, "prio", a[2]);
      last_status = 1;
      return;
    }
    int old = j->priority;
    if (cpu.manages(*j)) cpu.renice(*j, (int)n);
    else j->priority = (int)n;
    trace("RENICE", (j->sched_label.empty() ? j->command : j->sched_label) + ": priority " +
                        std::to_string(old) + " -> " + std::to_string(n));
    printf("[%d] %s: priority %d -> %ld\n", j->id, j->command.c_str(), old, n);
    fflush(stdout);
    schedule_tick();                                      // a more urgent job may preempt now
    last_status = 0;
    return;
  }
  Command inner = cmd;
  inner.argv.erase(inner.argv.begin(), inner.argv.begin() + 2);
  if (!inner.pipeline.empty()) {             // prio N a | b: the priority of the whole pipeline
    auto& a0 = inner.pipeline[0].argv;
    a0.erase(a0.begin(), a0.begin() + 2);
    if (a0.empty()) { fprintf(stderr, "prio: usage: prio N COMMAND [ARGS...]   or   prio N %%JOB\n"); last_status = 2; return; }
  }
  // Drop "prio N" from the source text shown by `jobs`.
  std::string t = cmd.text;
  for (int word = 0; word < 2; ++word) {
    size_t i = t.find_first_not_of(" \t");
    i = (i == std::string::npos) ? t.size() : t.find_first_of(" \t", i);
    t = (i == std::string::npos) ? "" : t.substr(i);
  }
  size_t s = t.find_first_not_of(" \t");
  inner.text = (s == std::string::npos) ? "" : t.substr(s);

  BuiltinFn fn = inner.pipeline.empty() ? find_builtin(inner.argv[0]) : nullptr;
  if (fn && !inner.background) run_builtin_inline(fn, inner);   // built-ins run in the shell
  else launch(inner, fn, (int)n);
}

// Run a built-in inside the shell process, applying redirections temporarily:
// the original descriptors are saved with dup() and restored afterwards.
void Shell::run_builtin_inline(BuiltinFn fn, const Command& cmd) {
  fflush(stdout);
  fflush(stderr);
  int saved[3] = {-1, -1, -1};
  bool ok = true;
  for (const Redirect& r : cmd.redirs) {
    int target = open_redirect(r);
    if (target < 0) { ok = false; break; }
    if (saved[r.fd] < 0) saved[r.fd] = dup(r.fd);
    dup2(target, r.fd);
    close(target);
  }
  int status = ok ? fn(*this, cmd.argv) : 1;
  fflush(stdout);
  fflush(stderr);
  for (int fd = 0; fd < 3; ++fd)
    if (saved[fd] >= 0) { dup2(saved[fd], fd); close(saved[fd]); }
  last_status = status;
}

// ---------------------------------------------------------------------------
// Process creation
// ---------------------------------------------------------------------------

// Executed in the child after fork(): never returns.
void Shell::child_exec(const Command& cmd, BuiltinFn fn, bool scheduled) {
  // 1. New process group.  When the kernel schedules the job (live off) a
  //    foreground job takes the terminal itself, as in Deliverable 1; when the
  //    shell schedules it, the shell hands over the terminal at dispatch.
  setpgid(0, 0);
  if (!cmd.background && !scheduled) give_terminal_to(getpid());

  // 2. Normal signal handling for the program: nothing blocked, nothing ignored.
  sigset_t none;
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, nullptr);
  for (int s : {SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGCHLD, SIGPIPE}) signal(s, SIG_DFL);
  if (sigfd_ >= 0) close(sigfd_);
  cpu.forget_all();            // this copy of the scheduler belongs to the parent
  kern.drop_inherited();       // ...and so do the memory and semaphores (the parent keeps serving them)
  if (scheduled) prctl(PR_SET_PDEATHSIG, SIGKILL);   // a stopped child must not outlive the shell

  // 3. Background jobs must not steal the shell's input: stdin <- /dev/null.
  if (cmd.background) {
    int nul = open("/dev/null", O_RDONLY);
    if (nul >= 0) { dup2(nul, STDIN_FILENO); close(nul); }
  }

  // 4. Redirections (a pipeline's redirections belong to its stages).
  for (const Redirect& r : cmd.pipeline.empty() ? cmd.redirs : std::vector<Redirect>{}) {
    int fd = open_redirect(r);
    if (fd < 0) _exit(1);
    dup2(fd, r.fd);
    close(fd);
  }

  // 5. Scheduled: wait in the ready queue until the scheduler continues us.
  if (scheduled) raise(SIGSTOP);

  // 6. A pipeline: this process becomes its leader and creates the stages.
  if (!cmd.pipeline.empty()) run_pipeline(cmd);

  // 7. Built-in with '&': run it here and exit with its status.
  if (fn) {
    int st = fn(*this, cmd.argv);
    fflush(stdout);
    fflush(stderr);
    _exit(st);
  }

  // 8. Replace the process image.
  std::vector<char*> args;
  for (const auto& a : cmd.argv) args.push_back(const_cast<char*>(a.c_str()));
  args.push_back(nullptr);
  execvp(args[0], args.data());
  int e = errno;
  if (e == ENOENT && cmd.argv[0].find('/') == std::string::npos)
    fprintf(stderr, "myshell: %s: command not found\n", args[0]);
  else
    fprintf(stderr, "myshell: %s: %s\n", args[0], strerror(e));
  _exit(e == ENOENT ? 127 : 126);
}

// ---------------------------------------------------------------------------
// Pipelines (Deliverable 4)
// ---------------------------------------------------------------------------
// Runs in the job's first process, a forked copy of the shell that the
// scheduler already treats as the job (it is the process-group leader).  It
// creates one child per stage, connected by kernel pipes:
//
//     stage 0 stdout -> pipe 0 -> stage 1 stdin,  stage 1 stdout -> pipe 1 -> ...
//
// Every stage is in the leader's process group, so the scheduler's SIGSTOP /
// SIGCONT, Ctrl-C and Ctrl-Z reach the whole pipeline at once, and the
// scheduler's /proc probe sees all stages as descendants of the leader.  A
// stage's own redirections are applied after the pipe, so they win (as in
// sh).  The leader waits for all stages and exits with the status of the
// LAST one; if the last stage was killed by a signal, it dies of the same one.
void Shell::run_pipeline(const Command& cmd) {
  const size_t n = cmd.pipeline.size();
  sigset_t term, old;
  sigemptyset(&term);
  for (int sg : {SIGINT, SIGQUIT, SIGTERM, SIGHUP}) sigaddset(&term, sg);
  sigprocmask(SIG_BLOCK, &term, &old);        // decided below, after the stages exist
  std::vector<pid_t> pids;
  int in = -1;                                 // read end of the previous pipe
  for (size_t i = 0; i < n; ++i) {
    int fds[2] = {-1, -1};
    if (i + 1 < n && pipe2(fds, O_CLOEXEC) < 0) {
      fprintf(stderr, "myshell: pipe: %s\n", strerror(errno));
      break;
    }
    pid_t pid = fork();
    if (pid < 0) {
      fprintf(stderr, "myshell: fork: %s\n", strerror(errno));
      break;
    }
    if (pid == 0) {                            // ---- stage i ----
      sigprocmask(SIG_SETMASK, &old, nullptr);
      if (in >= 0) { dup2(in, STDIN_FILENO); close(in); }
      if (i + 1 < n) { dup2(fds[1], STDOUT_FILENO); close(fds[0]); close(fds[1]); }
      const Command& st = cmd.pipeline[i];
      for (const Redirect& r : st.redirs) {
        int fd = open_redirect(r);
        if (fd < 0) _exit(1);
        dup2(fd, r.fd);
        close(fd);
      }
      if (BuiltinFn fn = find_builtin(st.argv[0])) {   // ls | grep txt: our own ls
        int rc = fn(*this, st.argv);
        fflush(stdout);
        fflush(stderr);
        _exit(rc);
      }
      std::vector<char*> args;
      for (const auto& a : st.argv) args.push_back(const_cast<char*>(a.c_str()));
      args.push_back(nullptr);
      execvp(args[0], args.data());
      int e = errno;
      if (e == ENOENT && st.argv[0].find('/') == std::string::npos)
        fprintf(stderr, "myshell: %s: command not found\n", args[0]);
      else
        fprintf(stderr, "myshell: %s: %s\n", args[0], strerror(e));
      _exit(e == ENOENT ? 127 : 126);
    }
    pids.push_back(pid);                       // ---- leader ----
    if (in >= 0) close(in);
    if (i + 1 < n) { close(fds[1]); in = fds[0]; }
  }
  if (in >= 0) close(in);
  // Termination signals are for the stages; the leader stays to report how
  // the LAST stage ended (a Ctrl-C reaches every stage of the group).
  // A signal that arrived while the stages were being created (kill %1 right
  // after the job started) reached only the stages that existed then: pass it
  // on to the whole group, so no stage survives it.
  sigset_t pend;
  sigpending(&pend);
  for (int sg : {SIGINT, SIGQUIT, SIGTERM, SIGHUP}) signal(sg, SIG_IGN);
  sigprocmask(SIG_SETMASK, &old, nullptr);
  for (int sg : {SIGINT, SIGQUIT, SIGTERM, SIGHUP})
    if (sigismember(&pend, sg) == 1) kill(0, sg);
  int last = 0;
  for (size_t i = 0; i < pids.size(); ++i) {
    int st = 0;
    while (waitpid(pids[i], &st, 0) < 0 && errno == EINTR) {}
    if (i + 1 == pids.size()) last = st;
  }
  if (pids.size() < n) _exit(1);
  if (WIFSIGNALED(last)) {
    int sg = WTERMSIG(last);
    signal(sg, SIG_DFL);
    sigset_t one;
    sigemptyset(&one);
    sigaddset(&one, sg);
    sigprocmask(SIG_UNBLOCK, &one, nullptr);
    raise(sg);
    _exit(128 + sg);
  }
  _exit(WIFEXITED(last) ? WEXITSTATUS(last) : 1);
}

void Shell::launch(const Command& cmd, BuiltinFn fn, int priority) {
  // Flush buffered output first, otherwise the child would inherit a copy of
  // it and print it a second time.
  fflush(stdout);
  fflush(stderr);
  // `sched` itself is a scheduler (an experiment run with '&'): it is never
  // scheduled, or two schedulers would be stopping each other's processes.
  const bool scheduled = live && !(fn && cmd.argv[0] == "sched");

  // Deliverable 4: every program the job will run is authorized first; a
  // denial anywhere in a pipeline runs nothing.
  if (cmd.pipeline.empty()) {
    if (!fn && !authorize_program(cmd)) { last_status = 126; return; }
  } else {
    for (const Command& st : cmd.pipeline) {
      if (!find_builtin(st.argv[0]) && !authorize_program(st)) { last_status = 126; return; }
      for (const Redirect& r : st.redirs)
        if (!authorize_redirect(r)) { last_status = 126; return; }
    }
  }

  pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "myshell: fork failed: %s\n", strerror(errno));
    last_status = 1;
    return;
  }
  if (pid == 0) child_exec(cmd, fn, scheduled);

  // Parent.  Ignore errors: EACCES just means the child already exec'd.
  setpgid(pid, pid);
  Job& job = jobs.add(pid, pid, cmd.text, !cmd.background);
  job.priority = priority;
  job.owner = Security::get().user();
  if (cmd.pipeline.empty()) {
    job.sched_label = short_label(cmd.argv);
  } else {                                   // "cat|grep|sort"
    std::string l;
    for (const Command& st : cmd.pipeline) l += (l.empty() ? "" : "|") + st.argv[0].substr(st.argv[0].rfind('/') + 1);
    job.sched_label = l.size() > 15 ? l.substr(0, 14) + "~" : l;
  }

  if (scheduled) {
    // Wait for the child to stop itself just before exec.
    int st = 0;
    struct rusage ru{};
    pid_t got;
    while ((got = wait4(pid, &st, WUNTRACED, &ru)) < 0 && errno == EINTR) {}
    if (got > 0 && !WIFSTOPPED(st)) {
      update_from_status(job, st, ru);   // it died before it could start (e.g. a redirection failed)
    } else {
      job.sched_arrival_ms = now_ms();
      cpu.admit(job, job.id, job.sched_arrival_ms, job.serial);
      trace("ARRIVE", job.sched_label + ": created (pid " + std::to_string((int)pid) + ", prio " +
                          std::to_string(priority) + "), stopped in ready queue");
    }
  }

  if (cmd.background) {
    printf("[%d] %d\n", job.id, (int)pid);
    last_bg = pid;
    fflush(stdout);
    last_status = 0;
    schedule_tick();                      // it may get the CPU straight away
  } else {
    last_status = wait_foreground(job);
  }
}

// ---------------------------------------------------------------------------
// Waiting for the foreground job
// ---------------------------------------------------------------------------
int Shell::wait_foreground(Job& job) {
  if (!job.scheduled || !live) return wait_foreground_unscheduled(job);
  const int id = job.id;
  fg_job_id_ = id;
  job.foreground = true;

  // A job that is already continued (running, or blocked) owns the terminal now.
  if (const CpuEntry* e = cpu.entry_of(job))
    if (e->state == CpuEntry::State::Running || e->state == CpuEntry::State::Blocked) give_terminal_to(job.pgid);

  schedule_tick();
  for (;;) {
    Job* j = jobs.find_by_id(id);
    if (!j || j->finished() || j->state == JobState::Stopped) break;
    pending_sigs_.clear();
    pump(cpu.timeout_ms(), false);
    // Terminal signals the shell received: the user meant the foreground job,
    // but it was waiting in the ready queue, so the shell held the terminal.
    for (int s : pending_sigs_) {
      j = jobs.find_by_id(id);
      if (!j || j->finished() || j->state == JobState::Stopped) break;
      if (s == SIGTSTP) stop_for_user(*j, SIGTSTP);
      else cpu.deliver(*j, s);          // SIGINT / SIGQUIT: act on it now
    }
    pending_sigs_.clear();
  }
  return finish_foreground(id);
}

// Deliverable 1 behaviour, used when the kernel schedules the job.
int Shell::wait_foreground_unscheduled(Job& job) {
  const int id = job.id;
  fg_job_id_ = id;
  give_terminal_to(job.pgid);
  // Not a blocking wait4(): the shell keeps serving the system calls of its
  // processes (the foreground job may be waiting for a semaphore or a page).
  for (;;) {
    Job* j = jobs.find_by_id(id);
    if (!j || j->finished() || j->state == JobState::Stopped) break;
    pump(-1, false);
  }
  return finish_foreground(id);
}

// Take the terminal back and report how the foreground job ended.
int Shell::finish_foreground(int id) {
  fg_job_id_ = 0;
  give_terminal_to(shell_pgid_);
  if (interactive_) tcsetattr(tty_fd_, TCSADRAIN, &shell_tmodes_);  // undo terminal mode changes

  Job* j = jobs.find_by_id(id);
  if (!j) return 1;
  if (j->state == JobState::Stopped) {             // Ctrl-Z: keep the job, it is now a background job
    j->foreground = false;
    jobs.touch(*j);
    if (interactive_) fputc('\n', stdout);
    announce(*j);
    return 128 + j->stop_signal;
  }
  int rc;
  if (j->state == JobState::Done) {
    rc = j->exit_status;
  } else {                                         // killed by a signal
    rc = 128 + j->term_signal;
    if (j->term_signal == SIGINT) {
      if (interactive_) fputc('\n', stdout);
    } else if (j->term_signal != SIGPIPE) {
      fprintf(stderr, "myshell: pid %d terminated by signal %d (%s): %s\n", (int)j->pid, j->term_signal,
              strsignal(j->term_signal), j->command.c_str());
    }
  }
  j->notified = true;
  jobs.retire(id);
  return rc;
}

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------
void Shell::update_from_status(Job& job, int status, const struct rusage& ru) {
  job.cpu_user_ms = tv_ms(ru.ru_utime);
  job.cpu_sys_ms = tv_ms(ru.ru_stime);
  job.kern_minflt = ru.ru_minflt;
  job.kern_majflt = ru.ru_majflt;
  job.kern_maxrss_kb = ru.ru_maxrss;
  if (WIFSTOPPED(status)) {
    job.state = JobState::Stopped;
    job.stop_signal = WSTOPSIG(status);
    job.stop_count++;
  } else if (WIFEXITED(status)) {
    job.state = JobState::Done;
    job.exit_status = WEXITSTATUS(status);
    job.finish = Job::Clock::now();
  } else if (WIFSIGNALED(status)) {
    job.state = JobState::Terminated;
    job.term_signal = WTERMSIG(status);
    job.finish = Job::Clock::now();
  }
}

// Collect status changes of every child without blocking.  The scheduler's
// own stops never show up here: it consumes them itself when it confirms a
// stop, so a stop seen here was caused by the user (Ctrl-Z, kill -STOP from
// another terminal).
void Shell::reap_children(bool notify) {
  for (;;) {
    int status = 0;
    struct rusage ru{};
    pid_t pid = wait4(-1, &status, WNOHANG | WUNTRACED, &ru);
    if (pid <= 0) break;
    Job* j = jobs.find_by_pid(pid);
    if (!j) continue;
    update_from_status(*j, status, ru);
    if (j->state == JobState::Stopped) {
      if (cpu.manages(*j)) cpu.stopped_elsewhere(*j);
      jobs.touch(*j);
      if (j->id != fg_job_id_) stop_announce_.push_back(j->id);
    } else if (j->finished()) {
      if (cpu.manages(*j)) cpu.exited(*j);
    }
  }
  if (notify) flush_notifications();
}

// Report finished and stopped background jobs, then drop the finished ones.
void Shell::flush_notifications() {
  for (int id : stop_announce_)
    if (Job* j = jobs.find_by_id(id))
      if (j->state == JobState::Stopped && id != fg_job_id_) announce(*j);
  stop_announce_.clear();
  for (Job* j : jobs.active()) {
    if (!j->finished() || j->id == fg_job_id_) continue;
    if (!j->notified) announce(*j);
    j->notified = true;
    jobs.retire(j->id);
  }
}

void Shell::wait_for_change(int id, JobState old_state, int timeout_ms) {
  long end = proc::mono_ms() + timeout_ms;
  while (proc::mono_ms() < end) {
    pump(1, false);
    reap_children(true);
    Job* j = jobs.find_by_id(id);
    if (!j || j->state != old_state) return;
  }
}

// "[1]+  Done                     sleep 2"
void Shell::announce(const Job& job) {
  char mark = ' ';
  if (&job == jobs.current()) mark = '+';
  else if (&job == jobs.previous()) mark = '-';

  char desc[64];
  switch (job.state) {
    case JobState::Done:
      if (job.exit_status == 0) snprintf(desc, sizeof desc, "Done");
      else snprintf(desc, sizeof desc, "Exit %d", job.exit_status);
      break;
    case JobState::Terminated: {
      const char* n = signal_short_name(job.term_signal);
      if (job.term_signal == SIGTERM) snprintf(desc, sizeof desc, "Terminated");
      else if (job.term_signal == SIGKILL) snprintf(desc, sizeof desc, "Killed");
      else if (job.term_signal == SIGINT) snprintf(desc, sizeof desc, "Interrupt");
      else if (job.term_signal == SIGHUP) snprintf(desc, sizeof desc, "Hangup");
      else snprintf(desc, sizeof desc, "%s", n ? strsignal(job.term_signal) : "Signalled");
      break;
    }
    case JobState::Stopped: {
      const char* n = signal_short_name(job.stop_signal);
      snprintf(desc, sizeof desc, "Stopped (SIG%s)", n ? n : "?");
      break;
    }
    default:
      snprintf(desc, sizeof desc, "%s", to_string(job.state));
  }
  printf("[%d]%c  %-24s %s\n", job.id, mark, desc, job.command.c_str());
  fflush(stdout);
}

// ---------------------------------------------------------------------------
// Job control through the scheduler
// ---------------------------------------------------------------------------
Job* Shell::resolve_job(const std::string& spec, std::string& err) {
  std::string s = spec;
  if (!s.empty() && s[0] == '%') s.erase(0, 1);
  Job* j = nullptr;
  if (s.empty() || s == "+" || s == "%") {
    j = jobs.current();
    if (!j) err = "no current job";
  } else if (s == "-") {
    j = jobs.previous();
    if (!j) err = "no previous job";
  } else {
    for (char c : s)
      if (c < '0' || c > '9') { err = "invalid job specification: " + spec; return nullptr; }
    if (s.size() > 9) { err = "no such job: " + spec; return nullptr; }
    j = jobs.find_by_id(std::stoi(s));
    if (!j) err = "no such job: " + spec;
  }
  return j;
}

// The user stops a scheduled job (Ctrl-Z, kill -STOP): it leaves the ready
// queue and stays stopped until `bg`, `fg` or `kill -CONT`.
void Shell::stop_for_user(Job& job, int sig) {
  if (cpu.manages(job)) cpu.stop_for_user(job);
  else kill(-job.pgid, SIGSTOP);
  job.state = JobState::Stopped;
  job.stop_signal = sig;
  job.stop_count++;
  jobs.touch(job);
}

void Shell::resume_job(Job& job) {
  job.state = JobState::Running;
  jobs.touch(job);
  if (!cpu.manages(job)) {
    cpu.admit(job, job.id, job.sched_arrival_ms, job.serial);
    trace("RESUME", job.sched_label + ": back in the ready queue");
  }
  schedule_tick();
}

int Shell::signal_job(Job& job, int sig) {
  if (sig == 0) return kill(-job.pgid, 0);
  if (is_stop_signal(sig)) {
    if (job.state != JobState::Stopped) {
      stop_for_user(job, sig);
      announce(job);
    }
    return 0;
  }
  if (sig == SIGCONT) {
    if (job.state == JobState::Stopped) resume_job(job);
    return 0;
  }
  if (sig == SIGKILL) return kill(-job.pgid, SIGKILL);   // works on stopped processes too
  // Any other signal: a stopped job is put back in the queue first, then the
  // scheduler delivers the signal so the job acts on it at once.
  if (job.state == JobState::Stopped) resume_job(job);
  cpu.deliver(job, sig);
  return 0;
}

int Shell::foreground_job(Job& job) {
  if (job.scheduled && live) {
    fg_job_id_ = job.id;                 // before it can be dispatched: it gets the terminal
    if (job.state == JobState::Stopped) resume_job(job);
    job.foreground = true;
    jobs.touch(job);
    printf("%s\n", job.command.c_str());
    fflush(stdout);
    return wait_foreground(job);
  }
  if (job.state == JobState::Stopped) {
    kill(-job.pgid, SIGCONT);
    job.state = JobState::Running;
  }
  job.foreground = true;
  jobs.touch(job);
  printf("%s\n", job.command.c_str());
  fflush(stdout);
  return wait_foreground_unscheduled(job);
}

int Shell::background_job(Job& job) {
  if (job.state != JobState::Stopped) {
    fprintf(stderr, "bg: job %d already in background\n", job.id);
    return 0;
  }
  if (job.scheduled && live) {
    resume_job(job);
  } else {
    kill(-job.pgid, SIGCONT);
    job.state = JobState::Running;
    jobs.touch(job);
  }
  job.foreground = false;
  printf("[%d]%c %s &\n", job.id, &job == jobs.current() ? '+' : ' ', job.command.c_str());
  fflush(stdout);
  return 0;
}

// `sched live off`: every job goes back to the kernel.  `sched live on`: every
// running job is stopped and queued, so from now on the shell schedules it.
void Shell::set_live(bool on) {
  if (on == live) return;
  if (!on) {
    cpu.release_all();
    for (Job* j : jobs.active()) j->scheduled = false;
    live = false;
    return;
  }
  live = true;
  for (Job* j : jobs.active()) {
    if (j->finished()) continue;
    j->scheduled = true;
    if (j->state == JobState::Stopped) continue;   // stays stopped until bg/fg
    kill(-j->pgid, SIGSTOP);
    int st = 0;
    struct rusage ru{};
    pid_t got;
    while ((got = wait4(j->pid, &st, WUNTRACED, &ru)) < 0 && errno == EINTR) {}
    if (got > 0 && !WIFSTOPPED(st)) { update_from_status(*j, st, ru); continue; }
    if (j->sched_label.empty()) j->sched_label = j->command;
    j->sched_arrival_ms = now_ms();
    cpu.admit(*j, j->id, j->sched_arrival_ms, j->serial);
  }
  schedule_tick();
}

// ---------------------------------------------------------------------------
// Shutdown: never leave orphan children behind.
// ---------------------------------------------------------------------------
void Shell::cleanup_jobs() {
  cpu.forget_all();                              // no more scheduling decisions
  auto act = jobs.active();
  std::vector<Job*> alive;
  for (Job* j : act)
    if (!j->finished()) alive.push_back(j);
  if (alive.empty()) return;
  fprintf(stderr, "myshell: terminating %zu remaining job(s)\n", alive.size());
  for (Job* j : alive) {
    kill(-j->pgid, SIGHUP);
    kill(-j->pgid, SIGCONT);                     // a stopped process can't act on SIGHUP
  }
  for (Job* j : alive) {
    int status = 0;
    bool reaped = false;
    for (int i = 0; i < 300 && !reaped; ++i) {   // ~300 ms grace period
      reaped = waitpid(j->pid, &status, WNOHANG) != 0;
      if (!reaped) usleep(1000);
    }
    if (!reaped) {
      kill(-j->pgid, SIGKILL);
      waitpid(j->pid, &status, 0);
    }
  }
}
