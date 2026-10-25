/* mktest.c - edge cases of the shell's kernel interface (Deliverable 3).
 *
 *   mktest api            every request with bad or extreme arguments; prints OK/BAD per case
 *   mktest hold NAME MS   lock mutex NAME, hold it MS milliseconds, unlock
 *   mktest lock NAME      lock mutex NAME (sleeps while someone else holds it), unlock
 *   mktest fifo N         N child processes sleep on one semaphore in a known order;
 *                         N posts must wake them in exactly that (FIFO) order
 *   mktest garbage        send a malformed request: the shell must drop the connection
 *   mktest twice          try to open a second connection from the same process
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/mkernel.h"

static int bad = 0;
static void check(int ok, const char* what, long got) {
  printf("%s  %-62s (got %ld)\n", ok ? "OK " : "BAD", what, got);
  if (!ok) bad++;
}

static int api(void) {
  if (mk_connect_as("mktest") < 0) { fprintf(stderr, "mktest: run me from myshell\n"); return 2; }
  long r;
  r = mk_alloc(0);          check(r == -EINVAL, "alloc of 0 pages is refused (EINVAL)", r);
  r = mk_alloc(-5);         check(r == -EINVAL, "alloc of a negative number of pages is refused", r);
  r = mk_alloc(1000000);    check(r == -EINVAL || r == -ENOMEM, "alloc of a million pages is refused", r);
  long base = mk_alloc(2);  check(base >= 0, "alloc of 2 pages succeeds", base);
  struct mk_rep rep;
  int64_t v = mk_read_r(mk_addr(base, 0), &rep);
  check(rep.status == 0 && v == 0, "a fresh page reads as zero", (long)v);
  check((rep.flags & MKF_FAULT) != 0, "...and the first touch is a page fault", (long)rep.flags);
  mk_write_r(mk_addr(base, 3), 42, &rep);
  v = mk_read_r(mk_addr(base, 3), &rep);
  check(v == 42 && !(rep.flags & MKF_FAULT), "a stored word reads back (a hit)", (long)v);
  mk_read_r(mk_addr(base, 0) + 3, &rep);
  check(rep.status == -EINVAL, "an unaligned address is refused (EINVAL)", rep.status);
  mk_read_r(-8, &rep);
  check(rep.status == -EINVAL, "a negative address is refused (EINVAL)", rep.status);
  r = mk_free(base, 5);     check(r == -EINVAL, "free of more pages than allocated is refused", r);
  r = mk_free(-1, 1);       check(r == -EINVAL, "free of a negative page is refused", r);
  r = mk_free(base + 1, 1); check(r == 0, "free of the second page succeeds", r);
  r = mk_free(base + 1, 1); check(r == -EINVAL, "freeing it twice is refused", r);
  r = mk_shm("", 1);        check(r == -EINVAL, "a shared segment without a name is refused", r);
  r = mk_shm("mktest-none", 0); check(r == -ENOENT, "attaching a missing segment is refused (ENOENT)", r);
  r = mk_shm("mktest-seg", 5000); check(r == -ENOENT || r == -ENOMEM, "a 5000-page segment is refused", r);
  long s1 = mk_shm("mktest-seg", 1); check(s1 >= 0, "a 1-page shared segment is created", s1);
  long s2 = mk_shm("mktest-seg", 0); check(s2 == s1, "attaching it again gives the same address", s2);
  r = mk_shm("mktest-seg", 3); check(r == -EINVAL, "asking for more pages than it has is refused", r);

  r = mk_wait("mktest-nosuch"); check(r == -ENOENT, "waiting on a missing semaphore fails (ENOENT)", r);
  r = mk_post("mktest-nosuch"); check(r == -ENOENT, "posting a missing semaphore fails (ENOENT)", r);
  r = mk_sem_open("mktest-s", MK_SEMAPHORE, -1); check(r == -EINVAL, "a negative initial value is refused", r);
  r = mk_sem_open("mktest-s", 7, 1);   check(r == -EINVAL, "an unknown kind is refused", r);
  r = mk_sem_open("", MK_SEMAPHORE, 1); check(r == -EINVAL, "an empty name is refused", r);
  r = mk_sem_open("mktest-s", MK_SEMAPHORE, 1); check(r == 0, "a semaphore with value 1 is created", r);
  r = mk_sem_open("mktest-s", MK_MUTEX, 0); check(r == -EEXIST, "the same name as a mutex is refused (EEXIST)", r);
  r = mk_trywait("mktest-s"); check(r == 0, "trywait takes the value 1", r);
  r = mk_trywait("mktest-s"); check(r == -EAGAIN, "trywait at 0 fails at once (EAGAIN)", r);
  r = mk_post("mktest-s");    check(r == 0, "post", r);
  r = mk_wait("mktest-s");    check(r == 0, "wait at 1 succeeds without sleeping", r);
  r = mk_sem_open("mktest-m", MK_MUTEX, 0); check(r == 0, "a mutex is created", r);
  r = mk_unlock("mktest-m");  check(r == -EPERM, "unlocking a mutex nobody holds is refused (EPERM)", r);
  r = mk_lock("mktest-m");    check(r == 0, "lock", r);
  r = mk_lock("mktest-m");    check(r == -EDEADLK, "relocking a mutex it holds is refused (EDEADLK)", r);
  r = mk_unlock("mktest-m");  check(r == 0, "unlock", r);
  r = mk_unlock("mktest-m");  check(r == -EPERM, "unlocking it twice is refused (EPERM)", r);
  r = mk_sem_init("mktest-s", MK_SEMAPHORE, 3); check(r == 0, "re-initialising an idle semaphore works", r);
  for (int i = 0; i < 3; ++i) mk_trywait("mktest-s");
  r = mk_trywait("mktest-s"); check(r == -EAGAIN, "...with exactly the new value (3)", r);
  struct mk_req q = mk_make(99, NULL);
  int s = mk_call(&q, &rep);  check(s == -EINVAL, "an unknown request is refused (EINVAL)", s);
  printf("%s\n", bad ? "SOME CASES FAILED" : "all cases behaved as specified");
  return bad ? 1 : 0;
}

static long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

int main(int argc, char** argv) {
  if (argc < 2) { fprintf(stderr, "usage: mktest api|hold NAME MS|lock NAME|fifo N|garbage|twice\n"); return 2; }
  if (!strcmp(argv[1], "api")) return api();
  if (!strcmp(argv[1], "hold") && argc == 4) {
    mk_connect_as("holder");
    mk_sem_open(argv[2], MK_MUTEX, 0);
    mk_lock(argv[2]);
    printf("holder: pid %d locked %s, holds it for %s ms\n", (int)getpid(), argv[2], argv[3]);
    fflush(stdout);
    usleep((useconds_t)atol(argv[3]) * 1000);
    mk_unlock(argv[2]);
    printf("holder: unlocked %s\n", argv[2]);
    return 0;
  }
  if (!strcmp(argv[1], "lock") && argc == 3) {
    mk_connect_as("locker");
    mk_sem_open(argv[2], MK_MUTEX, 0);
    long t0 = now_ms();
    struct mk_rep r;
    int s = mk_wait_r(argv[2], &r);
    printf("locker: pid %d got %s after %ld ms (status %d)%s\n", (int)getpid(), argv[2], now_ms() - t0, s,
           (r.flags & MKF_OWNER_DIED) ? " - the previous owner died holding it; the shell released it" : "");
    mk_unlock(argv[2]);
    return 0;
  }
  if (!strcmp(argv[1], "fifo") && argc == 3) {
    int n = atoi(argv[2]);
    if (n < 1 || n > 50) return 2;
    mk_connect_as("fifo-parent");
    mk_sem_init("mktest-fifo", MK_SEMAPHORE, 0);
    int fds[2];
    if (pipe(fds) < 0) return 1;
    for (int i = 0; i < n; ++i) {
      if (fork() == 0) {                       /* child i: queue up i-th */
        mk_fd = -1;                            /* its own connection to the shell */
        char me[32];
        snprintf(me, sizeof me, "waiter %d", i);
        usleep((useconds_t)(i * 20000));
        mk_connect_as(me);
        mk_wait("mktest-fifo");
        char b = (char)i;
        if (write(fds[1], &b, 1) != 1) _exit(1);
        _exit(0);
      }
    }
    usleep((useconds_t)(n * 20000 + 200000));   /* all of them asleep on the semaphore, in order */
    close(fds[1]);
    int order_ok = 1;
    for (int i = 0; i < n; ++i) {
      mk_post("mktest-fifo");
      char b;
      if (read(fds[0], &b, 1) != 1) { order_ok = 0; break; }
      printf("post %d woke waiter %d\n", i + 1, (int)b);
      if (b != i) order_ok = 0;
    }
    while (wait(NULL) > 0) {}
    printf("FIFO order %s\n", order_ok ? "kept: the longest waiter was always woken first" : "VIOLATED");
    return order_ok ? 0 : 1;
  }
  if (!strcmp(argv[1], "garbage")) {
    mk_connect_as("garbage");
    char junk[5] = {1, 2, 3, 4, 5};
    send(mk_fd, junk, sizeof junk, 0);
    char buf[256];
    ssize_t k = recv(mk_fd, buf, sizeof buf, 0);
    printf("garbage: after a malformed request the shell %s\n", k == 0 ? "closed the connection (as it should)" : "replied?!");
    return k == 0 ? 0 : 1;
  }
  if (!strcmp(argv[1], "twice")) {
    mk_connect_as("twice");
    int first = mk_fd;
    mk_fd = -1;
    int r = mk_connect_as("twice-again");
    printf("twice: second connection from the same process %s\n", r < 0 ? "refused (as it should)" : "accepted?!");
    mk_fd = first;
    long b = mk_alloc(1);
    printf("twice: the first connection still works (%s)\n", b >= 0 ? "alloc ok" : "alloc failed");
    return r < 0 && b >= 0 ? 0 : 1;
  }
  fprintf(stderr, "mktest: unknown mode\n");
  return 2;
}
