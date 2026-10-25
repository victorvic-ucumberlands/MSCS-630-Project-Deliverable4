// builtins.hpp - built-in commands (cd, pwd, ls, kill, jobs, fg, bg, ...).
#pragma once

#include <string>
#include <vector>

class Shell;

// A built-in receives the shell and its full argv (argv[0] = command name) and
// returns an exit status (0 = success).  Messages for the user go to stdout,
// diagnostics to stderr, so redirection works on built-ins too.
using BuiltinFn = int (*)(Shell&, const std::vector<std::string>&);

// Returns the handler for `name`, or nullptr if `name` is not a built-in.
BuiltinFn find_builtin(const std::string& name);

// `sched` (Deliverable 2) lives in sched_builtin.cpp.
int builtin_sched(Shell& sh, const std::vector<std::string>& args);

// `mem` and `sem` (Deliverable 3) live in mem_builtin.cpp.
int builtin_mem(Shell& sh, const std::vector<std::string>& args);
int builtin_sem(Shell& sh, const std::vector<std::string>& args);

// Signal helpers shared with the shell core (job notifications).
const char* signal_short_name(int sig);   // "TERM", "KILL", ... or nullptr
