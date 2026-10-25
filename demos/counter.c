/* counter.c - a race condition on a shared counter, and its cure (Deliverable 3).
 *
 *   counter NAME ITER [--lock MUTEX | --sem SEM] [--seg SEG | --file PATH] [-w US]
 *   counter --show SEG | --show-file PATH
 *   counter --reset SEG | --reset-file PATH
 *
 * Adds 1 to a shared counter ITER times with a read-modify-write:
 *     v = counter;   (work)   counter = v + 1;
 * The counter lives in word 0 of the shell's shared memory segment SEG
 * (default "counter"), or in a real file with --file.  Several instances run
 * as separate processes; if one loses the CPU between its read and its write,
 * the others' increments in the meantime are overwritten: lost updates.
 *
 * With --lock MUTEX (or --sem SEM, a semaphore with value 1) every
 * read-modify-write is a critical section bracketed by lock/unlock, so the
 * final value is exactly the sum of all increments.
 *   -w US   compute for US microseconds between the read and the write
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/mkernel.h"

static long now_us(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static void usage(void) {
  fprintf(stderr, "usage: counter NAME ITER [--lock MUTEX | --sem SEM] [--seg SEG | --file PATH] [-w US]\n"
                  "       counter --show SEG | --reset SEG | --show-file PATH | --reset-file PATH\n");
  exit(2);
}

static int file_fd = -1;
static long base = 0;

static int64_t load(void) {
  if (file_fd >= 0) {
    int64_t v = 0;
    if (pread(file_fd, &v, sizeof v, 0) != (ssize_t)sizeof v) v = 0;
    return v;
  }
  return mk_read(mk_addr(base, 0));
}

static void store(int64_t v) {
  if (file_fd >= 0) {
    if (pwrite(file_fd, &v, sizeof v, 0) != (ssize_t)sizeof v) perror("pwrite");
    return;
  }
  mk_write(mk_addr(base, 0), v);
}

int main(int argc, char** argv) {
  if (argc < 2) usage();
  if (!strcmp(argv[1], "--show") || !strcmp(argv[1], "--reset") || !strcmp(argv[1], "--show-file") ||
      !strcmp(argv[1], "--reset-file")) {
    if (argc != 3) usage();
    int is_file = strstr(argv[1], "file") != NULL;
    if (is_file) {
      file_fd = open(argv[2], O_RDWR | O_CREAT, 0644);
      if (file_fd < 0) { perror(argv[2]); return 1; }
    } else {
      if (mk_connect_as("counter") < 0) { fprintf(stderr, "counter: run me from myshell\n"); return 2; }
      base = mk_shm(argv[2], 1);
      if (base < 0) { fprintf(stderr, "counter: shared segment %s: %s\n", argv[2], strerror((int)-base)); return 1; }
    }
    if (!strncmp(argv[1], "--reset", 7)) { store(0); printf("counter in %s reset to 0\n", argv[2]); }
    else printf("counter in %s = %lld\n", argv[2], (long long)load());
    return 0;
  }
  if (argc < 3) usage();
  const char* name = argv[1];
  long iter = atol(argv[2]);
  const char* lock = NULL;
  const char* seg = "counter";
  const char* path = NULL;
  int kind = 0;
  long work_us = 0;
  for (int i = 3; i < argc; ++i) {
    if (!strcmp(argv[i], "--lock") && i + 1 < argc) { lock = argv[++i]; kind = MK_MUTEX; }
    else if (!strcmp(argv[i], "--sem") && i + 1 < argc) { lock = argv[++i]; kind = MK_SEMAPHORE; }
    else if (!strcmp(argv[i], "--seg") && i + 1 < argc) seg = argv[++i];
    else if (!strcmp(argv[i], "--file") && i + 1 < argc) path = argv[++i];
    else if (!strcmp(argv[i], "-w") && i + 1 < argc) work_us = atol(argv[++i]);
    else usage();
  }
  if (iter < 1) usage();
  if (mk_connect_as(name) < 0) { fprintf(stderr, "counter: run me from myshell\n"); return 2; }
  if (path) {
    file_fd = open(path, O_RDWR | O_CREAT, 0644);
    if (file_fd < 0) { perror(path); return 1; }
  } else {
    base = mk_shm(seg, 1);
    if (base < 0) { fprintf(stderr, "counter: shared segment %s: %s\n", seg, strerror((int)-base)); return 1; }
  }
  if (lock) {
    int s = mk_sem_open(lock, kind, 1);
    if (s < 0) { fprintf(stderr, "counter: %s: %s\n", lock, strerror(-s)); return 1; }
  }
  printf("%s: pid %d adds 1 to the counter in %s %ld times, %s\n", name, (int)getpid(), path ? path : seg, iter,
         lock ? (kind == MK_MUTEX ? "each time inside mutex" : "each time inside semaphore") : "WITHOUT synchronization");
  if (lock) printf("%s:   critical section protected by '%s'\n", name, lock);
  fflush(stdout);
  long t0 = now_us();
  for (long k = 0; k < iter; ++k) {
    if (lock) mk_wait(lock);                   /* enter the critical section */
    int64_t v = load();
    if (work_us) {
      long end = now_us() + work_us;
      while (now_us() < end) {}
    }
    store(v + 1);
    if (lock) mk_post(lock);                   /* leave it */
  }
  printf("%s: done, %ld increments in %ld ms\n", name, iter, (now_us() - t0) / 1000);
  return 0;
}
