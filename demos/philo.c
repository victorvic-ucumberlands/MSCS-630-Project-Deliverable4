/* philo.c - one dining philosopher as a real process (Deliverable 3).
 *
 *   philo ID N MEALS [--naive | --ordered | --waiter] [--think MS] [--eat MS] [--pause MS] [-v]
 *
 * N philosophers sit around a table with one fork between each pair; fork i
 * is the shell mutex "forkI".  Philosopher ID needs fork ID (left) and fork
 * (ID+1) % N (right) to eat.  Each philosopher is a separate process started
 * from the shell, so the shell's scheduler and its mutexes see them all.
 *
 *   --naive    take the left fork, then the right one.  If every philosopher
 *              holds a left fork, each waits for a fork its neighbour holds:
 *              a cycle - deadlock.  The shell detects the cycle and reports it.
 *              (--pause MS between the two forks makes this happen reliably.)
 *   --ordered  take the lower-numbered fork first (resource ordering).  The
 *              last philosopher reaches for fork 0 before fork N-1, so a cycle
 *              of waits cannot form: no deadlock.            (default)
 *   --waiter   at most N-1 philosophers may try to eat at once (a counting
 *              semaphore "room" with value N-1): someone always gets both forks.
 *
 * If the shell refuses a lock because it would close a cycle (`sem config
 * --deadlock fail`), the philosopher puts its first fork down, waits a little
 * and tries again - deadlock recovery by backing off.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/mkernel.h"

static long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void usage(void) {
  fprintf(stderr, "usage: philo ID N MEALS [--naive|--ordered|--waiter] [--think MS] [--eat MS] [--pause MS] [-v]\n");
  exit(2);
}

int main(int argc, char** argv) {
  if (argc < 4) usage();
  int id = atoi(argv[1]), n = atoi(argv[2]), meals = atoi(argv[3]);
  if (n < 2 || n > 32 || id < 0 || id >= n || meals < 1) usage();
  enum { NAIVE, ORDERED, WAITER } mode = ORDERED;
  long think = 20, eat = 20, pause_ms = 0;
  int verbose = 0;
  for (int i = 4; i < argc; ++i) {
    if (!strcmp(argv[i], "--naive")) mode = NAIVE;
    else if (!strcmp(argv[i], "--ordered")) mode = ORDERED;
    else if (!strcmp(argv[i], "--waiter")) mode = WAITER;
    else if (!strcmp(argv[i], "--think") && i + 1 < argc) think = atol(argv[++i]);
    else if (!strcmp(argv[i], "--eat") && i + 1 < argc) eat = atol(argv[++i]);
    else if (!strcmp(argv[i], "--pause") && i + 1 < argc) pause_ms = atol(argv[++i]);
    else if (!strcmp(argv[i], "-v")) verbose = 1;
    else usage();
  }
  char me[32];
  snprintf(me, sizeof me, "philo %d", id);
  if (mk_connect_as(me) < 0) { fprintf(stderr, "philo: run me from myshell\n"); return 2; }

  int left = id, right = (id + 1) % n;
  int first = left, second = right;
  if (mode == ORDERED && second < first) { first = right; second = left; }
  char f1[16], f2[16];
  snprintf(f1, sizeof f1, "fork%d", first);
  snprintf(f2, sizeof f2, "fork%d", second);
  if (mk_sem_open(f1, MK_MUTEX, 0) || mk_sem_open(f2, MK_MUTEX, 0) ||
      (mode == WAITER && mk_sem_open("room", MK_SEMAPHORE, n - 1))) {
    fprintf(stderr, "%s: cannot open the forks (do semaphores with these names exist as another kind?)\n", me);
    return 1;
  }
  printf("%s: pid %d, forks %d (left) and %d (right); takes fork %d first [%s]\n", me, (int)getpid(), left, right,
         first, mode == NAIVE ? "naive: left then right" : mode == ORDERED ? "ordered: lower number first"
                                                                          : "waiter: at most N-1 at the table");
  fflush(stdout);

  long waited = 0, longest = 0, backoffs = 0;
  unsigned seed = (unsigned)getpid();
  for (int m = 1; m <= meals; ++m) {
    if (think) usleep((useconds_t)think * 1000);              /* think */
    long hungry = now_ms();
    if (mode == WAITER) mk_wait("room");
    for (;;) {
      struct mk_rep r;
      mk_wait_r(f1, &r);
      if (verbose) { printf("%s: picks up fork %d%s\n", me, first, (r.flags & MKF_OWNER_DIED) ? " (its holder had died)" : ""); fflush(stdout); }
      if (pause_ms) usleep((useconds_t)pause_ms * 1000);
      int s = mk_wait_r(f2, &r);
      if (s == 0) {
        if (verbose) { printf("%s: picks up fork %d\n", me, second); fflush(stdout); }
        break;
      }
      if (s == -EDEADLK) {                                    /* the shell refused: it would deadlock */
        ++backoffs;
        printf("%s: the shell refused fork %d (it would close a deadlock cycle); puts fork %d down and retries\n", me,
               second, first);
        fflush(stdout);
        mk_unlock(f1);
        usleep((useconds_t)(10000 + rand_r(&seed) % 40000));
        continue;
      }
      fprintf(stderr, "%s: lock of fork %d failed: %s\n", me, second, strerror(-s));
      return 1;
    }
    long w = now_ms() - hungry;
    waited += w;
    if (w > longest) longest = w;
    printf("%s: eats (meal %d/%d) after waiting %ld ms\n", me, m, meals, w);
    fflush(stdout);
    if (eat) usleep((useconds_t)eat * 1000);                  /* eat */
    mk_unlock(f2);
    mk_unlock(f1);
    if (mode == WAITER) mk_post("room");
  }
  printf("%s: finished %d meals; waited %ld ms in total for forks (longest %ld ms)%s\n", me, meals, waited, longest,
         backoffs ? "" : "");
  if (backoffs) printf("%s: backed off %ld time(s) after a refused lock\n", me, backoffs);
  return 0;
}
