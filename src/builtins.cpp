// builtins.cpp - the built-in commands required by Deliverable 1:
//   cd pwd exit echo clear ls cat mkdir rmdir rm touch kill   (+ jobs fg bg help)
//
// Conventions
//   * every built-in returns an exit status (0 = success, non-zero = failure)
//   * results go to stdout and diagnostics to stderr, so "ls > f" and
//     "rm x 2> err" work exactly as for external programs
//   * built-ins validate their arguments and print "name: reason" on failure;
//     they never crash on bad input
#include "builtins.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#include "shell.hpp"

using Args = std::vector<std::string>;

// ---------------------------------------------------------------------------
// Signal name table (for kill and job notifications)
// ---------------------------------------------------------------------------
namespace {
struct SigEntry { const char* name; int num; };
const SigEntry kSignals[] = {
    {"HUP", SIGHUP},   {"INT", SIGINT},   {"QUIT", SIGQUIT}, {"ABRT", SIGABRT},
    {"KILL", SIGKILL}, {"USR1", SIGUSR1}, {"SEGV", SIGSEGV}, {"USR2", SIGUSR2},
    {"PIPE", SIGPIPE}, {"ALRM", SIGALRM}, {"TERM", SIGTERM}, {"CHLD", SIGCHLD},
    {"CONT", SIGCONT}, {"STOP", SIGSTOP}, {"TSTP", SIGTSTP}, {"TTIN", SIGTTIN},
    {"TTOU", SIGTTOU}};

bool all_digits(const std::string& s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}

// "9", "KILL", "SIGKILL", "kill" -> signal number.  Rejects everything else.
bool parse_signal(const std::string& text, int& out) {
  if (all_digits(text)) {
    if (text.size() > 3) return false;
    int n = std::atoi(text.c_str());
    if (n > 64) return false;
    out = n;
    return true;
  }
  std::string up;
  for (char c : text) up += (char)std::toupper((unsigned char)c);
  if (up.compare(0, 3, "SIG") == 0) up.erase(0, 3);
  for (const auto& e : kSignals)
    if (up == e.name) { out = e.num; return true; }
  return false;
}

// Strict decimal pid parser (rejects "12abc", "", overflow).
bool parse_pid(const std::string& s, long& out) {
  std::string body = (!s.empty() && (s[0] == '-' || s[0] == '+')) ? s.substr(1) : s;
  if (!all_digits(body) || body.size() > 10) return false;
  out = std::strtol(s.c_str(), nullptr, 10);
  return true;
}

// write() the whole buffer, retrying on EINTR / short writes.
bool write_all(int fd, const char* buf, size_t n) {
  while (n > 0) {
    ssize_t w = write(fd, buf, n);
    if (w < 0) { if (errno == EINTR) continue; return false; }
    buf += w;
    n -= (size_t)w;
  }
  return true;
}
}  // namespace

const char* signal_short_name(int sig) {
  for (const auto& e : kSignals) if (e.num == sig) return e.name;
  return nullptr;
}

// ---------------------------------------------------------------------------
// cd / pwd / exit / echo / clear
// ---------------------------------------------------------------------------
static int builtin_cd(Shell&, const Args& a) {
  if (a.size() > 2) { fprintf(stderr, "cd: too many arguments\n"); return 1; }

  std::string target;
  bool print_dir = false;
  if (a.size() == 1) {                                   // cd  -> $HOME
    const char* home = getenv("HOME");
    if (!home || !*home) { fprintf(stderr, "cd: HOME not set\n"); return 1; }
    target = home;
  } else if (a[1] == "-") {                              // cd -  -> previous directory
    const char* old = getenv("OLDPWD");
    if (!old || !*old) { fprintf(stderr, "cd: OLDPWD not set\n"); return 1; }
    target = old;
    print_dir = true;
  } else {
    target = a[1];
  }

  char prev[PATH_MAX];
  if (!getcwd(prev, sizeof prev)) prev[0] = '\0';
  if (chdir(target.c_str()) < 0) {
    fprintf(stderr, "cd: %s: %s\n", target.c_str(), strerror(errno));
    return 1;
  }
  char now[PATH_MAX];
  if (getcwd(now, sizeof now)) {
    setenv("OLDPWD", prev, 1);
    setenv("PWD", now, 1);
    if (print_dir) printf("%s\n", now);
  }
  return 0;
}

static int builtin_pwd(Shell&, const Args& a) {
  if (a.size() > 1) { fprintf(stderr, "pwd: too many arguments\n"); return 1; }
  char buf[PATH_MAX];
  if (!getcwd(buf, sizeof buf)) { fprintf(stderr, "pwd: %s\n", strerror(errno)); return 1; }
  printf("%s\n", buf);
  return 0;
}

static int builtin_exit(Shell& sh, const Args& a) {
  if (a.size() > 2) { fprintf(stderr, "exit: too many arguments\n"); return 1; }
  int code = sh.last_status;
  if (a.size() == 2) {
    long v;
    if (!parse_pid(a[1], v)) {
      fprintf(stderr, "exit: %s: numeric argument required\n", a[1].c_str());
      return 2;                                          // do not exit on bad input
    }
    code = (int)(((v % 256) + 256) % 256);               // exit codes are 8-bit
  }
  // Like bash: refuse the first exit while stopped jobs exist.
  if (sh.jobs.has_stopped() && !sh.exit_warned) {
    fprintf(stderr, "exit: there are stopped jobs (use 'jobs'; exit again to force)\n");
    sh.exit_warned = true;
    return 1;
  }
  sh.exit_requested = true;
  sh.exit_code = code;
  return code;
}

static int builtin_echo(Shell&, const Args& a) {
  size_t i = 1;
  bool newline = true;
  if (i < a.size() && a[i] == "-n") { newline = false; ++i; }
  for (bool first = true; i < a.size(); ++i, first = false) {
    if (!first) putchar(' ');
    fputs(a[i].c_str(), stdout);
  }
  if (newline) putchar('\n');
  return 0;
}

static int builtin_clear(Shell&, const Args&) {
  if (isatty(STDOUT_FILENO)) {
    fputs("\033[H\033[2J\033[3J", stdout);               // home, erase screen, erase scrollback
    return 0;
  }
  fprintf(stderr, "clear: standard output is not a terminal (nothing to clear)\n");
  return 0;
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------
static std::string mode_string(mode_t m) {
  char s[] = "----------";
  if (S_ISDIR(m)) s[0] = 'd';
  else if (S_ISLNK(m)) s[0] = 'l';
  else if (S_ISCHR(m)) s[0] = 'c';
  else if (S_ISBLK(m)) s[0] = 'b';
  else if (S_ISFIFO(m)) s[0] = 'p';
  else if (S_ISSOCK(m)) s[0] = 's';
  const mode_t bits[9] = {S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP,
                          S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH};
  for (int i = 0; i < 9; ++i) if (m & bits[i]) s[1 + i] = "rwx"[i % 3];
  return s;
}

// Print one entry; `full` is the path used for stat(), `name` what is displayed.
static void ls_entry(const std::string& full, const std::string& name, bool lng) {
  if (!lng) { printf("%s\n", name.c_str()); return; }
  struct stat st;
  if (lstat(full.c_str(), &st) < 0) {
    printf("?????????? ? ? ? ? ? %s\n", name.c_str());
    return;
  }
  struct passwd* pw = getpwuid(st.st_uid);
  struct group* gr = getgrgid(st.st_gid);
  char when[32];
  struct tm tmv;
  localtime_r(&st.st_mtime, &tmv);
  strftime(when, sizeof when, "%b %e %H:%M:%S", &tmv);
  printf("%s %3lu %-8s %-8s %8lld %s %s", mode_string(st.st_mode).c_str(),
         (unsigned long)st.st_nlink, pw ? pw->pw_name : std::to_string(st.st_uid).c_str(),
         gr ? gr->gr_name : std::to_string(st.st_gid).c_str(), (long long)st.st_size, when,
         name.c_str());
  if (S_ISLNK(st.st_mode)) {
    char tgt[PATH_MAX];
    ssize_t n = readlink(full.c_str(), tgt, sizeof tgt - 1);
    if (n > 0) { tgt[n] = '\0'; printf(" -> %s", tgt); }
  }
  putchar('\n');
}

static int builtin_ls(Shell&, const Args& a) {
  bool all = false, lng = false, opts_done = false;
  std::vector<std::string> paths;
  for (size_t i = 1; i < a.size(); ++i) {
    const std::string& s = a[i];
    if (!opts_done && s == "--") { opts_done = true; continue; }
    if (!opts_done && s.size() > 1 && s[0] == '-') {
      for (size_t k = 1; k < s.size(); ++k) {
        if (s[k] == 'a') all = true;
        else if (s[k] == 'l') lng = true;
        else if (s[k] == '1') {}                          // already one per line
        else { fprintf(stderr, "ls: invalid option -- '%c'\n", s[k]); return 2; }
      }
    } else {
      paths.push_back(s);
    }
  }
  if (paths.empty()) paths.push_back(".");

  int rc = 0;
  std::vector<std::string> files, dirs;
  for (const auto& p : paths) {
    struct stat st;
    if (stat(p.c_str(), &st) < 0) {
      fprintf(stderr, "ls: cannot access '%s': %s\n", p.c_str(), strerror(errno));
      rc = 2;
    } else if (S_ISDIR(st.st_mode)) {
      dirs.push_back(p);
    } else {
      files.push_back(p);
    }
  }
  std::sort(files.begin(), files.end());
  std::sort(dirs.begin(), dirs.end());

  for (const auto& f : files) ls_entry(f, f, lng);
  bool header = paths.size() > 1;
  bool first_block = files.empty();
  for (const auto& d : dirs) {
    DIR* dp = opendir(d.c_str());
    if (!dp) {
      fprintf(stderr, "ls: cannot open directory '%s': %s\n", d.c_str(), strerror(errno));
      rc = 2;
      continue;
    }
    std::vector<std::string> names;
    while (struct dirent* e = readdir(dp)) {
      if (!all && e->d_name[0] == '.') continue;          // hide dotfiles unless -a
      names.push_back(e->d_name);
    }
    closedir(dp);
    std::sort(names.begin(), names.end());                // plain byte order (deterministic)
    if (header) { if (!first_block) putchar('\n'); printf("%s:\n", d.c_str()); }
    first_block = false;
    for (const auto& n : names)
      ls_entry(d == "/" ? "/" + n : d + "/" + n, n, lng);
  }
  return rc;
}

// ---------------------------------------------------------------------------
// cat
// ---------------------------------------------------------------------------
// Copy fd -> stdout.  Returns false if reading/writing failed.
static bool cat_fd(int fd, const char* label, bool& rc_err) {
  char buf[8192];
  for (;;) {
    ssize_t n = read(fd, buf, sizeof buf);
    if (n == 0) return true;
    if (n < 0) {
      if (errno == EINTR) continue;
      fprintf(stderr, "cat: %s: %s\n", label, strerror(errno));
      rc_err = true;
      return true;
    }
    if (!write_all(STDOUT_FILENO, buf, (size_t)n)) return false;  // e.g. EPIPE: stop quietly
  }
}

static int builtin_cat(Shell&, const Args& a) {
  fflush(stdout);                                          // keep ordering with stdio output
  bool err = false;
  if (a.size() == 1) {                                     // no operands: copy stdin
    cat_fd(STDIN_FILENO, "stdin", err);
    return err ? 1 : 0;
  }
  for (size_t i = 1; i < a.size(); ++i) {
    if (a[i] == "-") { if (!cat_fd(STDIN_FILENO, "stdin", err)) break; continue; }
    int fd = open(a[i].c_str(), O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cat: %s: %s\n", a[i].c_str(), strerror(errno)); err = true; continue; }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
      fprintf(stderr, "cat: %s: Is a directory\n", a[i].c_str());
      err = true;
      close(fd);
      continue;
    }
    bool ok = cat_fd(fd, a[i].c_str(), err);
    close(fd);
    if (!ok) break;
  }
  return err ? 1 : 0;
}

// ---------------------------------------------------------------------------
// mkdir / rmdir / rm / touch
// ---------------------------------------------------------------------------
// mkdir -p: create every missing component; an existing directory is not an error.
static int mkdir_p(const std::string& path) {
  if (path.empty()) { errno = ENOENT; return -1; }
  for (size_t pos = 1; pos <= path.size(); ++pos) {
    if (pos != path.size() && path[pos] != '/') continue;
    std::string prefix = path.substr(0, pos);
    if (mkdir(prefix.c_str(), 0777) < 0 && errno != EEXIST) return -1;
  }
  struct stat st;
  if (stat(path.c_str(), &st) < 0) return -1;
  if (!S_ISDIR(st.st_mode)) { errno = EEXIST; return -1; }
  return 0;
}

static int builtin_mkdir(Shell&, const Args& a) {
  bool parents = false, opts_done = false;
  std::vector<std::string> dirs;
  for (size_t i = 1; i < a.size(); ++i) {
    if (!opts_done && a[i] == "--") { opts_done = true; continue; }
    if (!opts_done && a[i] == "-p") parents = true;
    else if (!opts_done && a[i].size() > 1 && a[i][0] == '-') {
      fprintf(stderr, "mkdir: invalid option -- '%s'\n", a[i].c_str() + 1);
      return 2;
    } else dirs.push_back(a[i]);
  }
  if (dirs.empty()) { fprintf(stderr, "mkdir: missing operand\n"); return 1; }
  int rc = 0;
  for (const auto& d : dirs) {
    int r = parents ? mkdir_p(d) : mkdir(d.c_str(), 0777);
    if (r < 0) {
      fprintf(stderr, "mkdir: cannot create directory '%s': %s\n", d.c_str(), strerror(errno));
      rc = 1;
    }
  }
  return rc;
}

static int builtin_rmdir(Shell&, const Args& a) {
  if (a.size() < 2) { fprintf(stderr, "rmdir: missing operand\n"); return 1; }
  int rc = 0;
  for (size_t i = 1; i < a.size(); ++i) {
    if (rmdir(a[i].c_str()) < 0) {
      fprintf(stderr, "rmdir: failed to remove '%s': %s\n", a[i].c_str(), strerror(errno));
      rc = 1;
    }
  }
  return rc;
}

// rm removes files only (the spec says "remove a file"); directories are
// refused with a hint instead of being deleted recursively.  -f silences
// "no such file" errors.
static int builtin_rm(Shell&, const Args& a) {
  bool force = false, opts_done = false;
  std::vector<std::string> files;
  for (size_t i = 1; i < a.size(); ++i) {
    if (!opts_done && a[i] == "--") { opts_done = true; continue; }
    if (!opts_done && a[i] == "-f") force = true;
    else if (!opts_done && a[i].size() > 1 && a[i][0] == '-') {
      fprintf(stderr, "rm: invalid option -- '%s' (only -f is supported)\n", a[i].c_str() + 1);
      return 2;
    } else files.push_back(a[i]);
  }
  if (files.empty()) {
    if (force) return 0;
    fprintf(stderr, "rm: missing operand\n");
    return 1;
  }
  int rc = 0;
  for (const auto& f : files) {
    struct stat st;
    if (lstat(f.c_str(), &st) < 0) {
      if (force && errno == ENOENT) continue;
      fprintf(stderr, "rm: cannot remove '%s': %s\n", f.c_str(), strerror(errno));
      rc = 1;
    } else if (S_ISDIR(st.st_mode)) {
      fprintf(stderr, "rm: cannot remove '%s': Is a directory (use rmdir)\n", f.c_str());
      rc = 1;
    } else if (unlink(f.c_str()) < 0) {
      fprintf(stderr, "rm: cannot remove '%s': %s\n", f.c_str(), strerror(errno));
      rc = 1;
    }
  }
  return rc;
}

// touch: update timestamps if the file exists, otherwise create it empty.
static int builtin_touch(Shell&, const Args& a) {
  bool opts_done = false;
  std::vector<std::string> files;
  for (size_t i = 1; i < a.size(); ++i) {
    if (!opts_done && a[i] == "--") { opts_done = true; continue; }
    if (!opts_done && a[i].size() > 1 && a[i][0] == '-') {
      fprintf(stderr, "touch: invalid option -- '%s'\n", a[i].c_str() + 1);
      return 2;
    }
    files.push_back(a[i]);
  }
  if (files.empty()) { fprintf(stderr, "touch: missing file operand\n"); return 1; }
  int rc = 0;
  for (const auto& f : files) {
    if (utimensat(AT_FDCWD, f.c_str(), nullptr, 0) == 0) continue;   // existed: mtime/atime = now
    int saved = errno;
    if (saved == ENOENT) {
      int fd = open(f.c_str(), O_WRONLY | O_CREAT, 0644);
      if (fd >= 0) { close(fd); continue; }
      saved = errno;
    }
    fprintf(stderr, "touch: cannot touch '%s': %s\n", f.c_str(), strerror(saved));
    rc = 1;
  }
  return rc;
}

// ---------------------------------------------------------------------------
// kill [-s SIG | -SIG] pid|%job ...      kill -l
// ---------------------------------------------------------------------------
static void kill_usage() {
  fprintf(stderr, "kill: usage: kill [-s SIGNAL | -SIGNAL] pid|%%job ... | kill -l\n");
}

static int builtin_kill(Shell& sh, const Args& a) {
  if (a.size() < 2) { kill_usage(); return 2; }
  if (a[1] == "-l") {
    for (const auto& e : kSignals) printf("%2d) SIG%s\n", e.num, e.name);
    return 0;
  }

  size_t i = 1;
  int sig = SIGTERM;
  if (a[1] == "-s") {
    if (a.size() < 3) { kill_usage(); return 2; }
    if (!parse_signal(a[2], sig)) {
      fprintf(stderr, "kill: invalid signal specification: %s\n", a[2].c_str());
      return 2;
    }
    i = 3;
  } else if (a[1] == "--") {
    i = 2;
  } else if (a[1].size() > 1 && a[1][0] == '-') {
    if (!parse_signal(a[1].substr(1), sig)) {
      fprintf(stderr, "kill: invalid signal specification: %s\n", a[1].c_str() + 1);
      return 2;
    }
    i = 2;
  }
  if (i >= a.size()) { kill_usage(); return 2; }

  sh.reap_children(true);          // make sure job states are current
  int rc = 0;
  for (; i < a.size(); ++i) {
    const std::string& t = a[i];
    Job* job = nullptr;
    pid_t target = 0;

    if (!t.empty() && t[0] == '%') {                       // job spec -> whole process group
      std::string err;
      job = sh.resolve_job(t, err);
      if (!job) { fprintf(stderr, "kill: %s\n", err.c_str()); rc = 1; continue; }
      target = -job->pgid;
    } else {
      long pid;
      if (!parse_pid(t, pid)) {
        fprintf(stderr, "kill: invalid pid: '%s'\n", t.c_str());
        rc = 1;
        continue;
      }
      if (pid <= 0) {                                      // 0 = our group, -1 = everything
        fprintf(stderr, "kill: refusing to signal pid %ld (process groups / all processes are not allowed)\n", pid);
        rc = 1;
        continue;
      }
      if (pid == (long)sh.shell_pid) {
        fprintf(stderr, "kill: refusing to signal the shell itself (use 'exit')\n");
        rc = 1;
        continue;
      }
      target = (pid_t)pid;
      job = sh.jobs.find_by_pid((pid_t)pid);
    }

    // A job the shell schedules: stopping and continuing go through the
    // scheduler (a SIGCONT sent directly would let it run beside the process
    // holding the CPU), and other signals are delivered so it acts at once.
    if (job && job->scheduled && sh.live && !job->finished()) {
      const int id = job->id;
      const JobState old = job->state;
      if (sh.signal_job(*job, sig) < 0) {
        fprintf(stderr, "kill: (%s) - %s\n", t.c_str(), strerror(errno));
        rc = 1;
        continue;
      }
      if (sig != 0 && sig != SIGCONT && sig != SIGSTOP && sig != SIGTSTP && sig != SIGTTIN && sig != SIGTTOU)
        sh.wait_for_change(id, old == JobState::Stopped ? JobState::Running : old, 500);
      continue;
    }

    if (::kill(target, sig) < 0) {
      fprintf(stderr, "kill: (%s) - %s\n", t.c_str(), strerror(errno));
      rc = 1;
      continue;
    }
    if (!job || sig == 0) continue;                        // not one of our jobs / existence probe

    // Keep the job table in sync with what the signal will do.
    const int id = job->id;
    const JobState old = job->state;
    if (sig == SIGCONT) {
      if (old == JobState::Stopped) { job->state = JobState::Running; sh.jobs.touch(*job); }
      continue;
    }
    // A stopped process cannot act on a pending terminating signal until it is
    // continued, so wake it (SIGKILL needs no help).
    if (old == JobState::Stopped && sig != SIGKILL &&
        (sig == SIGTERM || sig == SIGHUP || sig == SIGINT || sig == SIGQUIT))
      ::kill(target, SIGCONT);
    if (old != JobState::Stopped || sig == SIGTERM || sig == SIGHUP || sig == SIGINT ||
        sig == SIGQUIT || sig == SIGKILL)
      sh.wait_for_change(id, old, 500);
  }
  return rc;
}

// ---------------------------------------------------------------------------
// jobs / fg / bg
// ---------------------------------------------------------------------------
static int builtin_jobs(Shell& sh, const Args& a) {
  bool lng = false, pids = false, all = false;
  for (size_t i = 1; i < a.size(); ++i) {
    if (a[i].size() < 2 || a[i][0] != '-') { fprintf(stderr, "jobs: unexpected argument: %s\n", a[i].c_str()); return 2; }
    for (size_t k = 1; k < a[i].size(); ++k) {
      if (a[i][k] == 'l') lng = true;
      else if (a[i][k] == 'p') pids = true;
      else if (a[i][k] == 'a') all = true;
      else { fprintf(stderr, "jobs: invalid option -- '%c' (use -l, -p or -a)\n", a[i][k]); return 2; }
    }
  }
  sh.reap_children(true);

  if (all) {   // accounting table: every job record, finished ones included
    std::vector<const Job*> rows;
    for (const Job& j : sh.jobs.history()) rows.push_back(&j);
    for (Job* j : sh.jobs.active()) rows.push_back(j);
    std::sort(rows.begin(), rows.end(), [](const Job* x, const Job* y) { return x->serial < y->serial; });
    // TURN = exit - start; WAIT = time in the ready queue; RESP = first time on
    // the CPU - start; HELD = time holding the CPU; BLOCK = time blocked in the
    // kernel; CPU = CPU time the kernel charged (wait4); SLICES = dispatches.
    printf("%-4s %-3s %-7s %-11s %-9s %-4s %-8s %-8s %-8s %-8s %-9s %-7s %-6s %-5s %s\n", "REC", "JOB", "PID",
           "STATE", "RESULT", "PRIO", "TURN(ms)", "WAIT(ms)", "RESP(ms)", "HELD(ms)", "BLOCK(ms)", "CPU(ms)",
           "SLICES", "STOPS", "COMMAND");
    for (const Job* j : rows) {
      char result[24] = "-", turn[16] = "-", wait[16] = "-";
      if (j->state == JobState::Done) snprintf(result, sizeof result, "exit %d", j->exit_status);
      if (j->state == JobState::Terminated) snprintf(result, sizeof result, "sig %d", j->term_signal);
      if (j->finished()) {
        snprintf(turn, sizeof turn, "%ld", j->turnaround_ms());
        snprintf(wait, sizeof wait, "%ld", j->wait_ms());
      }
      printf("%-4lu %-3d %-7d %-11s %-9s %-4d %-8s %-8s %-8ld %-8ld %-9ld %-7ld %-6d %-5d %s\n", j->serial, j->id,
             (int)j->pid, to_string(j->state), result, j->priority, turn, wait, j->response_ms(), j->dispatched_ms,
             j->blocked_ms, j->cpu_user_ms + j->cpu_sys_ms, j->dispatches, j->stop_count, j->command.c_str());
    }
    return 0;
  }

  for (Job* j : sh.jobs.active()) {
    if (pids) { printf("%d\n", (int)j->pid); continue; }
    char mark = j == sh.jobs.current() ? '+' : (j == sh.jobs.previous() ? '-' : ' ');
    printf("[%d]%c  ", j->id, mark);
    if (lng) printf("%-6d ", (int)j->pid);
    printf("%-10s %s%s\n", to_string(j->state), j->command.c_str(),
           j->state == JobState::Running ? " &" : "");
  }
  return 0;
}

static int builtin_fg(Shell& sh, const Args& a) {
  if (a.size() > 2) { fprintf(stderr, "fg: too many arguments\n"); return 1; }
  std::string err;
  Job* j = sh.resolve_job(a.size() > 1 ? a[1] : "", err);
  if (!j) { fprintf(stderr, "fg: %s\n", err.c_str()); return 1; }
  return sh.foreground_job(*j);
}

static int builtin_bg(Shell& sh, const Args& a) {
  if (a.size() > 2) { fprintf(stderr, "bg: too many arguments\n"); return 1; }
  std::string err;
  Job* j = sh.resolve_job(a.size() > 1 ? a[1] : "", err);
  if (!j) { fprintf(stderr, "bg: %s\n", err.c_str()); return 1; }
  return sh.background_job(*j);
}

// source FILE: run FILE's commands in this shell (see Shell::source_file).
static int builtin_source(Shell& sh, const Args& a) {
  if (a.size() != 2) {
    fprintf(stderr, "source: usage: source FILE\n");
    return 2;
  }
  return sh.source_file(a[1]);
}

static int builtin_help(Shell&, const Args&) {
  puts("myshell built-in commands:\n"
       "  cd [dir]            change directory (cd = $HOME, cd - = previous)\n"
       "  pwd                 print working directory\n"
       "  echo [-n] text...   print text\n"
       "  clear               clear the terminal\n"
       "  ls [-a] [-l] [path...]   list files\n"
       "  cat [file...]       print files\n"
       "  mkdir [-p] dir...   create directories\n"
       "  rmdir dir...        remove empty directories\n"
       "  rm [-f] file...     remove files\n"
       "  touch file...       create file / update timestamp\n"
       "  kill [-SIG] pid|%job...   send a signal (kill -l lists signals)\n"
       "  jobs [-l] [-p] [-a] list jobs (-a = full accounting records)\n"
       "  fg [%job]           bring a job to the foreground\n"
       "  bg [%job]           resume a stopped job in the background\n"
       "  prio N COMMAND      run COMMAND with scheduling priority N (0-99, lower = more urgent)\n"
       "  prio N %job         change the priority of a job\n"
       "  sched ...           the CPU scheduler: policy, ps, trace, experiments (sched help)\n"
       "  mem ...             paged memory: frames, page tables, faults, replacement (mem help)\n"
       "  sem ...             semaphores and mutexes for processes (sem help)\n"
       "  source FILE         run the commands in FILE in this shell (also: . FILE)\n"
       "  exit [code]         leave the shell\n"
       "syntax: cmd &   cmd1 ; cmd2   > >> < 2>   'quotes' \"quotes\"   $VAR $? $$   # comment");
  return 0;
}

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------
BuiltinFn find_builtin(const std::string& name) {
  static const std::map<std::string, BuiltinFn> table = {
      {"cd", builtin_cd},       {"pwd", builtin_pwd},     {"exit", builtin_exit},
      {"echo", builtin_echo},   {"clear", builtin_clear}, {"ls", builtin_ls},
      {"cat", builtin_cat},     {"mkdir", builtin_mkdir}, {"rmdir", builtin_rmdir},
      {"rm", builtin_rm},       {"touch", builtin_touch}, {"kill", builtin_kill},
      {"jobs", builtin_jobs},   {"fg", builtin_fg},       {"bg", builtin_bg},
      {"help", builtin_help},   {"sched", builtin_sched},
      {"mem", builtin_mem},     {"sem", builtin_sem},     {"source", builtin_source},
      {".", builtin_source}};
  auto it = table.find(name);
  return it == table.end() ? nullptr : it->second;
}
