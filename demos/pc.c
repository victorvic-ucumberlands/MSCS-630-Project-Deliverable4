/* pc.c - the bounded-buffer Producer-Consumer problem with real processes
 * (Deliverable 3).
 *
 *   pc init N [-n BUF]                     create (or reset) a buffer of N slots
 *   pc producer ID COUNT [options]         put COUNT items into the buffer
 *   pc consumer ID COUNT [options]         take COUNT items out of it
 *   pc check LOG PRODUCERS COUNT           was every item consumed exactly once?
 *   pc show [-n BUF]                       the buffer's slots and indices
 *
 * The buffer is a shared memory segment of the shell ("buf" by default):
 *     word 0 = N (slots), 1 = in, 2 = out, 3 = count, 8.. = the N slots
 * and three objects synchronize it:
 *     BUF.empty  counting semaphore, initially N   (free slots)
 *     BUF.full   counting semaphore, initially 0   (filled slots)
 *     BUF.mutex  mutex                             (the buffer's indices)
 *
 *   producer:  P(empty); lock(mutex); slots[in] = item; in = (in+1) % N; unlock(mutex); V(full)
 *   consumer:  P(full);  lock(mutex); item = slots[out]; out = (out+1) % N; unlock(mutex); V(empty)
 *
 * A producer that finds the buffer full, or a consumer that finds it empty,
 * sleeps inside the shell until a slot or an item is available - it does not
 * spin.  An item is ID*1000000 + sequence number; every consumer appends
 * "PRODUCER SEQ" to a log (-l FILE, default pc.log) so `pc check` can count
 * lost and duplicated items.
 *
 * Options:
 *   -n BUF       buffer name (default buf)
 *   -l FILE      consumer log (default pc.log)
 *   -v           print every put / get
 *   -t MS        time to produce / consume one item (outside the critical section)
 *   -w US        work inside the critical section (between reading and updating the indices)
 *   --nosync     no semaphores: busy-wait on `count` and update the indices unprotected
 *   --bad-order  lock the mutex BEFORE waiting on empty/full (the classic deadlock)
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/mkernel.h"

enum { W_N = 0, W_IN = 1, W_OUT = 2, W_COUNT = 3, W_SLOTS = 8 };

static long base;
static char buf_name[24] = "buf";
static char s_empty[MK_NAME_MAX], s_full[MK_NAME_MAX], s_mutex[MK_NAME_MAX];

static long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}
static void spin_us(long us) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  long end = t.tv_sec * 1000000L + t.tv_nsec / 1000 + us;
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &t);
    if (t.tv_sec * 1000000L + t.tv_nsec / 1000 >= end) break;
  }
}
static int64_t get(long w) { return mk_read(mk_addr(base + w / (mk_page_size / MK_WORD), w % (mk_page_size / MK_WORD))); }
static void put(long w, int64_t v) { mk_write(mk_addr(base + w / (mk_page_size / MK_WORD), w % (mk_page_size / MK_WORD)), v); }

static void usage(void) {
  fprintf(stderr,
          "usage: pc init N [-n BUF]\n"
          "       pc producer ID COUNT [-n BUF] [-v] [-t MS] [-w US] [--nosync] [--bad-order]\n"
          "       pc consumer ID COUNT [-n BUF] [-l LOG] [-v] [-t MS] [-w US] [--nosync] [--bad-order]\n"
          "       pc check LOG PRODUCERS COUNT\n"
          "       pc show [-n BUF]\n");
  exit(2);
}

static void names(void) {
  snprintf(s_empty, sizeof s_empty, "%s.empty", buf_name);
  snprintf(s_full, sizeof s_full, "%s.full", buf_name);
  snprintf(s_mutex, sizeof s_mutex, "%s.mutex", buf_name);
}

static long pages_for(long n) { return (W_SLOTS + n) * MK_WORD / mk_page_size + 1; }

static int attach(const char* who, long create_slots) {
  if (mk_connect_as(who) < 0) { fprintf(stderr, "pc: run me from myshell\n"); exit(2); }
  base = mk_shm(buf_name, create_slots ? pages_for(create_slots) : 0);
  if (base < 0) {
    fprintf(stderr, "pc: buffer '%s': %s%s\n", buf_name, strerror((int)-base),
            base == -ENOENT ? " (create it first with 'pc init N')" : "");
    exit(1);
  }
  return 0;
}

/* ---- pc check -------------------------------------------------------------- */
static int check(const char* log, long producers, long count) {
  FILE* f = fopen(log, "r");
  if (!f) { perror(log); return 1; }
  long total = producers * count;
  int* seen = calloc((size_t)total, sizeof *seen);
  long lines = 0, bogus = 0, empty = 0, lost = 0, dup = 0, order = 0;
  long last[64][64];                           /* last seq per (consumer, producer) */
  for (int i = 0; i < 64; ++i)
    for (int j = 0; j < 64; ++j) last[i][j] = 0;
  long c, p, s;
  char line[128];
  while (fgets(line, sizeof line, f)) {
    if (sscanf(line, "%ld %ld %ld", &c, &p, &s) != 3) { ++bogus; continue; }
    ++lines;
    if (p == 0 && s == 0) { ++empty; continue; }   /* took an empty slot */
    if (p < 1 || p > producers || s < 1 || s > count) { ++bogus; continue; }
    seen[(p - 1) * count + (s - 1)]++;
    if (c >= 0 && c < 64 && p < 64) {
      if (s <= last[c][p]) ++order;
      last[c][p] = s;
    }
  }
  fclose(f);
  for (long i = 0; i < total; ++i) {
    if (seen[i] == 0) ++lost;
    if (seen[i] > 1) dup += seen[i] - 1;
  }
  printf("check %s: %ld items produced (%ld producers x %ld), %ld taken by consumers\n", log, total, producers, count,
         lines);
  printf("  lost (never consumed):      %ld\n", lost);
  printf("  duplicated (consumed twice): %ld\n", dup);
  printf("  empty slots taken:          %ld\n", empty);
  printf("  out of order (per producer, per consumer): %ld\n", order);
  printf("  corrupt values:             %ld\n", bogus);
  int ok = !lost && !dup && !empty && !order && !bogus && lines == total;
  printf("  verdict: %s\n", ok ? "CORRECT - every item consumed exactly once, in order"
                               : "WRONG - the buffer was corrupted by a race");
  free(seen);
  return ok ? 0 : 1;
}

int main(int argc, char** argv) {
  if (argc < 2) usage();
  const char* mode = argv[1];
  if (!strcmp(mode, "check")) {
    if (argc != 5) usage();
    return check(argv[2], atol(argv[3]), atol(argv[4]));
  }
  int verbose = 0, nosync = 0, bad_order = 0;
  long id = 0, count = 0, slots = 0, think_ms = 0, work_us = 0;
  const char* log = "pc.log";
  int argi = 2;
  if (!strcmp(mode, "init")) {
    if (argc < 3) usage();
    slots = atol(argv[2]);
    argi = 3;
    if (slots < 1 || slots > 1000) { fprintf(stderr, "pc: N must be 1..1000\n"); return 2; }
  } else if (!strcmp(mode, "producer") || !strcmp(mode, "consumer")) {
    if (argc < 4) usage();
    id = atol(argv[2]);
    count = atol(argv[3]);
    argi = 4;
    if (id < 1 || id > 63 || count < 1 || count > 999999) { fprintf(stderr, "pc: ID must be 1..63, COUNT 1..999999\n"); return 2; }
  } else if (strcmp(mode, "show")) {
    usage();
  }
  for (int i = argi; i < argc; ++i) {
    if (!strcmp(argv[i], "-n") && i + 1 < argc) snprintf(buf_name, sizeof buf_name, "%s", argv[++i]);
    else if (!strcmp(argv[i], "-l") && i + 1 < argc) log = argv[++i];
    else if (!strcmp(argv[i], "-v")) verbose = 1;
    else if (!strcmp(argv[i], "-t") && i + 1 < argc) think_ms = atol(argv[++i]);
    else if (!strcmp(argv[i], "-w") && i + 1 < argc) work_us = atol(argv[++i]);
    else if (!strcmp(argv[i], "--nosync")) nosync = 1;
    else if (!strcmp(argv[i], "--bad-order")) bad_order = 1;
    else usage();
  }
  names();
  char who[32];

  if (!strcmp(mode, "init")) {
    attach("pc init", slots);
    long existing = (long)get(W_N);
    if (existing && pages_for(existing) != pages_for(slots)) {
      fprintf(stderr, "pc: buffer '%s' exists with %ld slots in a segment of another size; use another name (-n)\n",
              buf_name, existing);
      return 1;
    }
    put(W_N, slots);
    put(W_IN, 0);
    put(W_OUT, 0);
    put(W_COUNT, 0);
    for (long i = 0; i < slots; ++i) put(W_SLOTS + i, 0);
    int e1 = mk_sem_init(s_empty, MK_SEMAPHORE, slots), e2 = mk_sem_init(s_full, MK_SEMAPHORE, 0),
        e3 = mk_sem_init(s_mutex, MK_MUTEX, 0);
    if (e1 || e2 || e3) {
      fprintf(stderr, "pc: cannot reset the semaphores (%s): are producers or consumers still running?\n",
              strerror(-(e1 ? e1 : e2 ? e2 : e3)));
      return 1;
    }
    printf("buffer '%s': %ld slots in shared memory; semaphores %s = %ld, %s = 0; mutex %s\n", buf_name, slots,
           s_empty, slots, s_full, s_mutex);
    return 0;
  }
  if (!strcmp(mode, "show")) {
    attach("pc show", 0);
    long n = (long)get(W_N);
    printf("buffer '%s': %ld slots, in=%lld out=%lld count=%lld\n  slots:", buf_name, n, (long long)get(W_IN),
           (long long)get(W_OUT), (long long)get(W_COUNT));
    for (long i = 0; i < n && i < 64; ++i) {
      int64_t v = get(W_SLOTS + i);
      if (v) printf(" [%lld.%lld]", (long long)(v / 1000000), (long long)(v % 1000000));
      else printf(" [ ]");
    }
    printf("\n");
    return 0;
  }

  int producer = !strcmp(mode, "producer");
  snprintf(who, sizeof who, "%s %ld", producer ? "producer" : "consumer", id);
  attach(who, 0);
  long n = (long)get(W_N);
  if (n < 1) { fprintf(stderr, "pc: buffer '%s' is not initialised (pc init N)\n", buf_name); return 1; }
  if (!nosync && (mk_sem_open(s_empty, MK_SEMAPHORE, n) || mk_sem_open(s_full, MK_SEMAPHORE, 0) ||
                  mk_sem_open(s_mutex, MK_MUTEX, 0))) {
    fprintf(stderr, "pc: cannot open the semaphores of '%s'\n", buf_name);
    return 1;
  }
  int logfd = -1;
  if (!producer) {
    logfd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd < 0) { perror(log); return 1; }
  }
  printf("%s: pid %d, %ld items, buffer '%s' (%ld slots), %s\n", who, (int)getpid(), count, buf_name, n,
         nosync ? "NO synchronization (busy-waits on count)"
                : bad_order ? "WRONG order: locks the mutex before waiting on the semaphore"
                            : "semaphores empty/full + mutex");
  fflush(stdout);

  long t0 = now_ms(), empties = 0;
  const long give_up_ms = 3000;
  for (long k = 1; k <= count; ++k) {
    if (producer && think_ms) usleep((useconds_t)think_ms * 1000);  /* produce the item */
    int64_t item = producer ? id * 1000000 + k : 0;
    long slot;
    if (!nosync) {
      if (bad_order) mk_lock(s_mutex);
      mk_wait(producer ? s_empty : s_full);   /* a free slot / a full slot (sleeps if none) */
      if (!bad_order) mk_lock(s_mutex);       /* the indices */
    } else {
      long since = now_ms();                  /* busy-wait for room / an item */
      for (;;) {
        int64_t c = get(W_COUNT);
        if (producer ? c < n : c > 0) break;
        if (now_ms() - since > give_up_ms) {
          fprintf(stderr, "%s: gave up after %ld ms waiting for %s: count=%lld in=%lld out=%lld (the shared state is "
                          "inconsistent)\n",
                  who, give_up_ms, producer ? "a free slot" : "an item", (long long)c, (long long)get(W_IN),
                  (long long)get(W_OUT));
          return 3;
        }
      }
    }
    /* ---- critical section ---- */
    if (producer) {
      slot = (long)get(W_IN);
      if (work_us) spin_us(work_us);
      put(W_SLOTS + slot, item);
      put(W_IN, (slot + 1) % n);
      put(W_COUNT, get(W_COUNT) + 1);
    } else {
      slot = (long)get(W_OUT);
      item = get(W_SLOTS + slot);
      if (work_us) spin_us(work_us);
      put(W_SLOTS + slot, 0);
      put(W_OUT, (slot + 1) % n);
      put(W_COUNT, get(W_COUNT) - 1);
    }
    long fill = (long)get(W_COUNT);
    /* ---- end of critical section ---- */
    if (!nosync) {
      mk_unlock(s_mutex);
      mk_post(producer ? s_full : s_empty);
    }
    if (verbose) {
      if (producer) printf("%s: put item %ld.%ld into slot %ld   (buffer %ld/%ld)\n", who, id, k, slot, fill, n);
      else if (item) printf("%s: got item %lld.%lld from slot %ld   (buffer %ld/%ld)\n", who, (long long)(item / 1000000),
                            (long long)(item % 1000000), slot, fill, n);
      else printf("%s: slot %ld was EMPTY\n", who, slot);
      fflush(stdout);
    }
    if (!producer) {
      if (!item) ++empties;
      char line[64];
      int len = snprintf(line, sizeof line, "%ld %lld %lld\n", id, (long long)(item / 1000000), (long long)(item % 1000000));
      if (write(logfd, line, (size_t)len) != len) perror("log");
      if (think_ms) usleep((useconds_t)think_ms * 1000);         /* consume the item */
    }
  }
  printf("%s: done, %ld items in %ld ms%s\n", who, count, now_ms() - t0,
         producer ? "" : (empties ? " (some slots were EMPTY!)" : ""));
  return 0;
}
