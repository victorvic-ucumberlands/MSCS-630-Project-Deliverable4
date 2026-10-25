/* mkernel.h - the "system call" interface between myshell and its processes
 * (Deliverable 3: memory management and process synchronization).
 *
 * myshell plays the role of the operating-system kernel for the processes it
 * starts.  It listens on a Unix-domain socket whose address it puts in the
 * environment variable MYSHELL_KERNEL, so every process the shell creates
 * inherits it.  A process that wants paged memory or a semaphore connects to
 * that socket (one connection per process; the shell learns the caller's pid
 * from the kernel with SO_PEERCRED) and issues requests.  Every request is
 * synchronous: the process sends one request and sleeps in recv() until the
 * shell replies.  The shell can therefore BLOCK a process simply by not
 * replying yet - which is how a semaphore wait or a page fault that has to
 * "read the disk" puts the process to sleep, exactly as a kernel would.
 *
 * Memory: a process has a virtual address space of fixed-size pages.  It asks
 * for pages with mk_alloc() and gives them back with mk_free().  Every load
 * and store is a request (mk_read / mk_write), so the shell sees every memory
 * reference, as a hardware MMU would: it translates the virtual address with
 * the process's page table, raises a page fault if the page is not in a
 * physical frame, picks a victim with the replacement policy (FIFO / LRU /
 * Clock) when every frame is in use, writes a dirty victim to swap, and loads
 * the page.  An access outside the allocated pages is answered with SIGSEGV.
 *
 * Synchronization: named counting semaphores and mutexes kept by the shell.
 * mk_wait() on a semaphore whose value is 0 (or mk_lock() on a mutex owned by
 * someone else) is not answered until the semaphore is posted, so the process
 * really sleeps; waiters are woken in FIFO order.
 *
 * This header is plain C (it is also compiled as C++ by the shell).  The
 * client functions are static inline, so a program only has to include it.
 */
#ifndef MYSHELL_MKERNEL_H
#define MYSHELL_MKERNEL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MK_ENV "MYSHELL_KERNEL"
#define MK_NAME_MAX 32
#define MK_WORD 8 /* loads and stores move one 64-bit word */

enum mk_op {
  MK_HELLO = 1,  /* name = label for displays.  rep.a = page size, rep.b = frames, rep.value = caller pid */
  MK_ALLOC,      /* a = number of pages.  rep.value = first virtual page of the new region */
  MK_FREE,       /* a = first page, b = number of pages */
  MK_READ,       /* a = virtual address.  rep.value = the word stored there */
  MK_WRITE,      /* a = virtual address, value = the word to store */
  MK_SHM,        /* name = shared segment, a = pages (0 = attach existing).  rep.value = first page */
  MK_SEM_OPEN,   /* name, kind (MK_SEMAPHORE / MK_MUTEX), value = initial value (created if new) */
  MK_SEM_INIT,   /* name, kind, value: (re)create with this value; refused while processes wait */
  MK_WAIT,       /* name: P() / lock - the reply is delayed until it succeeds */
  MK_TRYWAIT,    /* name: P() that fails with -EAGAIN instead of waiting */
  MK_POST,       /* name: V() / unlock */
  MK_INFO        /* rep.s[] = this process's memory statistics (see MK_INFO_*) */
};

enum mk_kind { MK_SEMAPHORE = 1, MK_MUTEX = 2 };

/* reply status 1: "try again" - a wait was woken without being handed the
 * semaphore (`sem config --handoff barge`); the client simply asks again. */
#define MK_RETRY 1

/* reply flags */
#define MKF_FAULT      0x01 /* the access raised a page fault */
#define MKF_MAJOR      0x02 /* ...and the page had to be read back from swap */
#define MKF_EVICT      0x04 /* a page was evicted to make room */
#define MKF_WRITEBACK  0x08 /* ...and it was dirty, so it was written to swap */
#define MKF_WAITED     0x10 /* a wait/lock had to sleep before it succeeded */
#define MKF_OWNER_DIED 0x20 /* a mutex was taken over from an owner that exited */

enum { MK_INFO_REFS, MK_INFO_FAULTS, MK_INFO_MAJOR, MK_INFO_RESIDENT, MK_INFO_PEAK, MK_INFO_VPAGES,
       MK_INFO_EVICTED, MK_INFO_N };

struct mk_req {
  int32_t op;
  int32_t kind;
  int64_t a;
  int64_t b;
  int64_t value;
  char name[MK_NAME_MAX];
};

struct mk_rep {
  int32_t status;               /* 0 or a negative errno value */
  uint32_t flags;               /* MKF_* */
  int64_t value;
  int64_t a, b;
  int32_t frame;                /* physical frame that holds the page (-1 if none) */
  int32_t victim_pid;           /* owner of the evicted page (0 = shared segment) */
  int64_t victim_page;          /* its virtual page (or page of the segment) */
  char victim[MK_NAME_MAX];     /* label of the evicted page's owner */
  int64_t s[MK_INFO_N];         /* MK_INFO statistics */
};

/* ------------------------------------------------------------------------ */
/* Client side                                                                */
/* ------------------------------------------------------------------------ */
static int mk_fd = -1;
static long mk_page_size = 0;
static long mk_frames = 0;

/* Connect to the shell (once).  Returns 0, or -1 if the program was not
 * started by myshell (or the shell is gone). */
static inline int mk_connect_as(const char* label) {
  if (mk_fd >= 0) return 0;
  const char* addr = getenv(MK_ENV);
  if (!addr || !*addr) { errno = ENOENT; return -1; }
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  size_t n = strlen(addr);
  if (n >= sizeof sa.sun_path) { close(fd); errno = ENAMETOOLONG; return -1; }
  memcpy(sa.sun_path, addr, n);
  if (addr[0] == '@') sa.sun_path[0] = '\0'; /* abstract socket */
  socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
  if (connect(fd, (struct sockaddr*)&sa, len) < 0) { int e = errno; close(fd); errno = e; return -1; }
  mk_fd = fd;
  struct mk_req q;
  struct mk_rep r;
  memset(&q, 0, sizeof q);
  q.op = MK_HELLO;
  if (label) snprintf(q.name, sizeof q.name, "%s", label);
  if (send(mk_fd, &q, sizeof q, 0) != (ssize_t)sizeof q) return -1;
  for (;;) {
    ssize_t k = recv(mk_fd, &r, sizeof r, 0);
    if (k == (ssize_t)sizeof r) break;
    if (k < 0 && errno == EINTR) continue;
    close(mk_fd);
    mk_fd = -1;
    errno = ECONNRESET;
    return -1;
  }
  mk_page_size = (long)r.a;
  mk_frames = (long)r.b;
  return 0;
}

/* One synchronous request.  Returns rep->status.  If the shell disappears the
 * process cannot continue (its memory lived in the shell), so it exits. */
static inline int mk_call(struct mk_req* q, struct mk_rep* r) {
  if (mk_fd < 0 && mk_connect_as(NULL) < 0) {
    fprintf(stderr, "mkernel: not started by myshell (%s is not set or unreachable)\n", MK_ENV);
    exit(2);
  }
  memset(r, 0, sizeof *r);
  for (;;) {
    ssize_t k = send(mk_fd, q, sizeof *q, MSG_NOSIGNAL);
    if (k == (ssize_t)sizeof *q) break;
    if (k < 0 && errno == EINTR) continue;
    fprintf(stderr, "mkernel: lost the connection to the shell\n");
    exit(2);
  }
  for (;;) {
    ssize_t k = recv(mk_fd, r, sizeof *r, 0);
    if (k == (ssize_t)sizeof *r) return r->status;
    if (k < 0 && errno == EINTR) continue;
    fprintf(stderr, "mkernel: lost the connection to the shell\n");
    exit(2);
  }
}

static inline struct mk_req mk_make(int op, const char* name) {
  struct mk_req q;
  memset(&q, 0, sizeof q);
  q.op = op;
  if (name) snprintf(q.name, sizeof q.name, "%s", name);
  return q;
}

/* Memory.  mk_alloc returns the first virtual page of the new region (or a
 * negative errno: -ENOMEM when memory + swap cannot hold it). */
static inline long mk_alloc(long npages) {
  struct mk_req q = mk_make(MK_ALLOC, NULL);
  struct mk_rep r;
  q.a = npages;
  int s = mk_call(&q, &r);
  return s < 0 ? s : (long)r.value;
}
static inline int mk_free(long first_page, long npages) {
  struct mk_req q = mk_make(MK_FREE, NULL);
  struct mk_rep r;
  q.a = first_page;
  q.b = npages;
  return mk_call(&q, &r);
}
static inline long mk_shm(const char* name, long npages) {
  struct mk_req q = mk_make(MK_SHM, name);
  struct mk_rep r;
  q.a = npages;
  int s = mk_call(&q, &r);
  return s < 0 ? s : (long)r.value;
}
/* Address of word `w` of virtual page `page`. */
static inline int64_t mk_addr(long page, long w) { return (int64_t)page * mk_page_size + w * MK_WORD; }
static inline int64_t mk_read_r(int64_t vaddr, struct mk_rep* r) {
  struct mk_req q = mk_make(MK_READ, NULL);
  q.a = vaddr;
  mk_call(&q, r);
  return r->value;
}
static inline int mk_write_r(int64_t vaddr, int64_t v, struct mk_rep* r) {
  struct mk_req q = mk_make(MK_WRITE, NULL);
  q.a = vaddr;
  q.value = v;
  return mk_call(&q, r);
}
static inline int64_t mk_read(int64_t vaddr) { struct mk_rep r; return mk_read_r(vaddr, &r); }
static inline int mk_write(int64_t vaddr, int64_t v) { struct mk_rep r; return mk_write_r(vaddr, v, &r); }
static inline int mk_info(struct mk_rep* r) { struct mk_req q = mk_make(MK_INFO, NULL); return mk_call(&q, r); }

/* Synchronization. */
static inline int mk_sem_open(const char* name, int kind, long initial) {
  struct mk_req q = mk_make(MK_SEM_OPEN, name);
  struct mk_rep r;
  q.kind = kind;
  q.value = initial;
  return mk_call(&q, &r);
}
static inline int mk_sem_init(const char* name, int kind, long value) {
  struct mk_req q = mk_make(MK_SEM_INIT, name);
  struct mk_rep r;
  q.kind = kind;
  q.value = value;
  return mk_call(&q, &r);
}
static inline int mk_wait_r(const char* name, struct mk_rep* r) {
  struct mk_req q = mk_make(MK_WAIT, name);
  int s;
  uint32_t seen = 0;
  while ((s = mk_call(&q, r)) == MK_RETRY) seen |= r->flags;   /* barging: woken, but must compete again */
  r->flags |= seen;
  return s;
}
static inline int mk_wait(const char* name) { struct mk_rep r; return mk_wait_r(name, &r); }
static inline int mk_trywait(const char* name) { struct mk_req q = mk_make(MK_TRYWAIT, name); struct mk_rep r; return mk_call(&q, &r); }
static inline int mk_post(const char* name) { struct mk_req q = mk_make(MK_POST, name); struct mk_rep r; return mk_call(&q, &r); }
/* A mutex is a semaphore of kind MK_MUTEX: it has an owner, only the owner
 * may unlock it, and the shell releases it if the owner dies. */
static inline int mk_lock(const char* name) { return mk_wait(name); }
static inline int mk_unlock(const char* name) { return mk_post(name); }

/* ------------------------------------------------------------------------ */
/* Reference strings (shared by the test program and `mem sim`, so a live    */
/* process and the simulator see exactly the same sequence)                  */
/* ------------------------------------------------------------------------ */
/*   "7,0,1,2,0,3"        explicit list; a 'w' after a page makes it a write ("3w")
 *   "loop:P:N"           pages 0..P-1 in order, N times (a sequential scan)
 *   "rand:N:P:SEED[:W]"  N uniformly random pages of 0..P-1 (W = % writes)
 *   "local:N:P:WS:SEED[:W]"  N references with locality: 90% fall in a working
 *                        set of WS consecutive pages that moves every 50 references
 * Returns the number of references (at most max) or -1 for a malformed spec. */
static inline unsigned long mk_lcg(unsigned long* s) {
  *s = *s * 6364136223846793005UL + 1442695040888963407UL;
  return (*s >> 33);
}
static inline int mk_gen(const char* spec, int* pages, unsigned char* writes, int max) {
  char kind[16] = {0};
  const char* colon = strchr(spec, ':');
  if (colon && colon - spec < (long)sizeof kind) memcpy(kind, spec, (size_t)(colon - spec));
  long v[6] = {0, 0, 0, 0, 0, 0};
  int nv = 0;
  if (colon) {
    const char* p = colon + 1;
    while (*p && nv < 6) {
      char* end;
      long x = strtol(p, &end, 10);
      if (end == p || x < 0) return -1;
      v[nv++] = x;
      if (*end == ':') p = end + 1;
      else if (*end == '\0') { p = end; break; }
      else return -1;
    }
    if (*p) return -1;
  }
  int n = 0;
  if (!colon) {                               /* explicit list */
    const char* p = spec;
    while (*p) {
      while (*p == ',' || *p == ' ') ++p;
      if (!*p) break;
      char* end;
      long x = strtol(p, &end, 10);
      if (end == p || x < 0 || x > 1000000) return -1;
      int w = 0;
      if (*end == 'w' || *end == 'W') { w = 1; ++end; }
      if (*end && *end != ',' && *end != ' ') return -1;
      if (n >= max) return -1;
      pages[n] = (int)x;
      writes[n] = (unsigned char)w;
      ++n;
      p = end;
    }
    return n;
  }
  if (!strcmp(kind, "loop")) {
    if (nv != 2 || v[0] < 1 || v[1] < 1 || v[0] * v[1] > max) return -1;
    for (long r = 0; r < v[1]; ++r)
      for (long pg = 0; pg < v[0]; ++pg) { pages[n] = (int)pg; writes[n] = 0; ++n; }
    return n;
  }
  if (!strcmp(kind, "rand")) {
    if ((nv != 3 && nv != 4) || v[0] < 1 || v[0] > max || v[1] < 1 || v[3] > 100) return -1;
    unsigned long s = (unsigned long)v[2] * 2654435761UL + 1;
    for (long i = 0; i < v[0]; ++i) {
      pages[n] = (int)(mk_lcg(&s) % (unsigned long)v[1]);
      writes[n] = (unsigned char)((long)(mk_lcg(&s) % 100) < v[3]);
      ++n;
    }
    return n;
  }
  if (!strcmp(kind, "local")) {
    if ((nv != 4 && nv != 5) || v[0] < 1 || v[0] > max || v[1] < 1 || v[2] < 1 || v[2] > v[1] || v[4] > 100)
      return -1;
    unsigned long s = (unsigned long)v[3] * 2654435761UL + 7;
    long base = 0;
    for (long i = 0; i < v[0]; ++i) {
      if (i % 50 == 0) base = (long)(mk_lcg(&s) % (unsigned long)v[1]);
      long pg;
      if (mk_lcg(&s) % 10 < 9) pg = (base + (long)(mk_lcg(&s) % (unsigned long)v[2])) % v[1];
      else pg = (long)(mk_lcg(&s) % (unsigned long)v[1]);
      pages[n] = (int)pg;
      writes[n] = (unsigned char)((long)(mk_lcg(&s) % 100) < v[4]);
      ++n;
    }
    return n;
  }
  return -1;
}

#endif /* MYSHELL_MKERNEL_H */
