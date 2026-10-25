/* memproc.c - a test process for the shell's memory manager (Deliverable 3).
 *
 *   memproc NAME PAGES REFS [options]
 *
 * Allocates PAGES pages of virtual memory from the shell, then makes the
 * memory references in REFS - a list such as 7,0,1,2,0,3 ('3w' = a write)
 * or a generator (loop:P:N, rand:N:P:SEED[:W%], local:N:P:WS:SEED[:W%]; see
 * src/mkernel.h).  Every reference is a real load or store that goes through
 * the shell, so the shell sees each one, handles the page faults and picks
 * the pages to replace.
 *
 * Every store writes a value unique to this process, page and moment, and
 * every load checks that it reads back exactly what was last stored there (or
 * 0 for a page never written).  So the run also verifies that data survives
 * being evicted to swap and loaded again, possibly into a different frame.
 *
 * Options:
 *   -v          print every reference: frame, hit or fault, what was evicted
 *   -W          make every reference a write
 *   -r N        repeat the reference string N times
 *   -c US       compute for US microseconds per reference (CPU work)
 *   -s MS       sleep MS milliseconds after every reference
 *   --hold MS   sleep MS milliseconds before exiting (to look at `mem` meanwhile)
 *   --free      give the pages back explicitly before exiting
 */
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

static void spin_us(long us) {
  long end = now_us() + us;
  volatile unsigned long x = 0;
  while (now_us() < end) x++;
}

static int64_t signature(const char* name, long page, long n) {
  uint64_t h = 1469598103934665603ULL;
  for (const char* p = name; *p; ++p) h = (h ^ (unsigned char)*p) * 1099511628211ULL;
  return (int64_t)(((h & 0xffffff) << 40) | ((uint64_t)(page & 0xffff) << 24) | ((uint64_t)n & 0xffffff)) | 1;
}

static void usage(void) {
  fprintf(stderr, "usage: memproc NAME PAGES REFS [-v] [-W] [-r N] [-c US] [-s MS] [--hold MS] [--free]\n"
                  "  REFS: 7,0,1,2 ('3w' = write) | loop:P:N | rand:N:P:SEED[:W%%] | local:N:P:WS:SEED[:W%%]\n");
  exit(2);
}

int main(int argc, char** argv) {
  if (argc < 4) usage();
  const char* name = argv[1];
  long npages = atol(argv[2]);
  const char* spec = argv[3];
  int verbose = 0, all_writes = 0, do_free = 0;
  long repeat = 1, work_us = 0, sleep_ms = 0, hold_ms = 0;
  for (int i = 4; i < argc; ++i) {
    if (!strcmp(argv[i], "-v")) verbose = 1;
    else if (!strcmp(argv[i], "-W")) all_writes = 1;
    else if (!strcmp(argv[i], "--free")) do_free = 1;
    else if (!strcmp(argv[i], "-r") && i + 1 < argc) repeat = atol(argv[++i]);
    else if (!strcmp(argv[i], "-c") && i + 1 < argc) work_us = atol(argv[++i]);
    else if (!strcmp(argv[i], "-s") && i + 1 < argc) sleep_ms = atol(argv[++i]);
    else if (!strcmp(argv[i], "--hold") && i + 1 < argc) hold_ms = atol(argv[++i]);
    else usage();
  }
  if (npages < 1 || repeat < 1) usage();
  static int pages[200000];
  static unsigned char writes[200000];
  int n = mk_gen(spec, pages, writes, 200000);
  if (n <= 0) { fprintf(stderr, "memproc: malformed reference string '%s'\n", spec); return 2; }

  if (mk_connect_as(name) < 0) {
    fprintf(stderr, "memproc: cannot reach the shell's memory manager (run me from myshell)\n");
    return 2;
  }
  long base = mk_alloc(npages);
  if (base < 0) {
    fprintf(stderr, "%s: allocation of %ld pages refused: %s\n", name, npages,
            base == -ENOMEM ? "out of memory (RAM + swap)" : strerror((int)-base));
    return 3;
  }
  printf("%s: pid %d allocated %ld pages = %ld KB (virtual pages %ld-%ld), page size %ld, %ld frames in the system\n",
         name, (int)getpid(), npages, npages * mk_page_size / 1024, base, base + npages - 1, mk_page_size, mk_frames);
  fflush(stdout);

  int64_t* expect = calloc((size_t)npages + 1, sizeof *expect);
  long mismatches = 0, stores = 0, faults = 0, major = 0;
  const long word = 1;                         /* the word of each page the test uses */
  for (long r = 0; r < repeat; ++r) {
    for (int i = 0; i < n; ++i) {
      long pg = pages[i];
      int w = all_writes || writes[i];
      struct mk_rep rep;
      int64_t addr = mk_addr(base + pg, word);
      if (w) {
        int64_t v = signature(name, pg, ++stores);
        mk_write_r(addr, v, &rep);
        if (rep.status == 0 && pg < npages) expect[pg] = v;
      } else {
        int64_t v = mk_read_r(addr, &rep);
        if (rep.status == 0 && pg < npages && v != expect[pg]) {
          ++mismatches;
          fprintf(stderr, "%s: DATA ERROR page %ld: read %lld, expected %lld\n", name, pg, (long long)v,
                  (long long)expect[pg]);
        }
      }
      if (rep.status != 0) {
        fprintf(stderr, "%s: reference to page %ld failed: %s\n", name, pg, strerror(-rep.status));
        return 1;
      }
      if (rep.flags & MKF_FAULT) ++faults;
      if (rep.flags & MKF_MAJOR) ++major;
      if (verbose) {
        char ev[96] = "";
        if (rep.flags & MKF_EVICT)
          snprintf(ev, sizeof ev, ", evicted %s%s", rep.victim, (rep.flags & MKF_WRITEBACK) ? " (dirty: written to swap)" : "");
        printf("%s: %-5s page %-3ld -> frame %-2d %s%s\n", name, w ? "write" : "read", pg, rep.frame,
               !(rep.flags & MKF_FAULT) ? "hit" : (rep.flags & MKF_MAJOR) ? "PAGE FAULT (major: read back from swap)"
                                                                          : "PAGE FAULT (minor: zero-filled)",
               ev);
        fflush(stdout);
      }
      if (work_us) spin_us(work_us);
      if (sleep_ms) usleep((useconds_t)sleep_ms * 1000);
    }
  }
  struct mk_rep info;
  mk_info(&info);
  long refs = (long)n * repeat;
  printf("%s: %ld references, %ld page faults (%ld minor, %ld major), hit ratio %.1f%%, peak resident %lld of %ld "
         "pages, data check %s (%ld mismatches)\n",
         name, refs, faults, faults - major, major, refs ? 100.0 * (double)(refs - faults) / (double)refs : 0.0,
         (long long)info.s[MK_INFO_PEAK], npages, mismatches ? "FAILED" : "OK", mismatches);
  fflush(stdout);
  if (hold_ms) usleep((useconds_t)hold_ms * 1000);
  if (do_free) {
    int s = mk_free(base, npages);
    printf("%s: freed its %ld pages (%s)\n", name, npages, s == 0 ? "ok" : strerror(-s));
    fflush(stdout);
  }
  free(expect);
  return mismatches ? 4 : 0;
}
