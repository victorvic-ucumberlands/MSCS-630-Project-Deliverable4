/* cpuburn.c - a small CPU-bound program used as a workload for the scheduler.
 *
 *   cpuburn NAME TOTAL_MS [CHUNK_MS]
 *
 * Busy-loops until it has consumed TOTAL_MS milliseconds of its OWN CPU time
 * (CLOCK_PROCESS_CPUTIME_ID, so the measurement is unaffected by being
 * preempted), printing a progress line every CHUNK_MS of CPU time:
 *
 *   A: 100/400 ms cpu (pid 1234, 213 ms elapsed)
 *
 * Two things make this useful as scheduler evidence:
 *   - the interleaving of the progress lines of several tasks shows the shell
 *     switching the CPU between real processes;
 *   - "cpu" advances only while the process is actually dispatched, while
 *     "elapsed" keeps growing, so the gap between them is the time the task
 *     spent waiting in the ready queue.
 *
 * Build: the project Makefile compiles this into demos/cpuburn.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static long now_ms(clockid_t clk) {
  struct timespec t;
  clock_gettime(clk, &t);
  return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s NAME TOTAL_MS [CHUNK_MS]\n", argv[0]);
    return 2;
  }
  const char* name = argv[1];
  long total = atol(argv[2]);
  long chunk = argc > 3 ? atol(argv[3]) : 100;
  if (total <= 0 || chunk <= 0) {
    fprintf(stderr, "%s: TOTAL_MS and CHUNK_MS must be positive\n", argv[0]);
    return 2;
  }

  long wall0 = now_ms(CLOCK_MONOTONIC);
  long next = chunk;
  volatile unsigned long sink = 0;   /* volatile: the loop must not be optimised away */

  for (;;) {
    for (int i = 0; i < 20000; ++i) sink += (unsigned long)i * 2654435761u;
    long cpu = now_ms(CLOCK_PROCESS_CPUTIME_ID);
    if (cpu >= next || cpu >= total) {
      printf("%s: %ld/%ld ms cpu (pid %d, %ld ms elapsed)\n", name, cpu < total ? cpu : total, total,
             (int)getpid(), now_ms(CLOCK_MONOTONIC) - wall0);
      fflush(stdout);
      while (next <= cpu) next += chunk;
    }
    if (cpu >= total) break;
  }
  return 0;
}
