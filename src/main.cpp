// main.cpp - entry point.
//
//   ./myshell                 interactive shell (or reads commands from stdin)
//   ./myshell script.msh      run a script file
//   ./myshell -e script.msh   same, but echo each line first (demo transcripts)
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "shell.hpp"

static void usage(const char* prog) {
  fprintf(stderr, "usage: %s [-e] [script-file]\n"
                  "  -e   echo each script line before running it\n", prog);
}

int main(int argc, char** argv) {
  bool echo = false;
  const char* script = nullptr;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-e")) echo = true;
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
    else if (!script && argv[i][0] != '-') script = argv[i];
    else { usage(argv[0]); return 2; }
  }

  // Input is read from a file descriptor so the shell can wait for input and
  // for its children at the same time (poll), keeping the scheduler running.
  int in = STDIN_FILENO;
  if (script) {
    in = open(script, O_RDONLY | O_CLOEXEC);
    if (in < 0) {
      fprintf(stderr, "myshell: %s: %s\n", script, strerror(errno));
      return 127;
    }
  }

  // Interactive mode (prompt + job-control signals) only when reading a terminal.
  bool interactive = !script && isatty(STDIN_FILENO);
  setvbuf(stdout, nullptr, _IOLBF, 0);  // line-buffered: keeps stdout/stderr ordering in logs
  Shell shell(interactive, echo);
  int rc = shell.run(in);
  if (script) close(in);
  return rc;
}
