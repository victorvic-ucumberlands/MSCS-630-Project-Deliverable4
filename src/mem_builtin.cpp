// mem_builtin.cpp - the `mem` and `sem` built-ins (Deliverable 3): the user
// interface of the shell's memory manager and of its semaphores/mutexes.
//
//   mem                       configuration, frame table, per-process usage
//   mem config [-f N] [-p BYTES] [-s PAGES] [-d MS]   physical memory, swap, swap I/O time
//   mem policy [fifo|lru|clock]                       page-replacement policy
//   mem frames | ps [-a] | pt PID|%JOB | stats | reset | trace [on|off]
//   mem shm [rm NAME] | peek NAME [WORD [COUNT]]
//   mem sim [-a fifo|lru|clock|opt|all] -f N[-M] [-t|-q] REFS   textbook simulation
//
//   sem                       every semaphore and mutex, owners and FIFO queues
//   sem create NAME [VALUE] | sem create -m NAME | sem post NAME | sem rm NAME | sem reset
//   sem clients | deadlock | trace [on|off] | config [--deadlock report|fail]
#include <signal.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "builtins.hpp"
#include "mkernel.h"
#include "shell.hpp"

using Args = std::vector<std::string>;

namespace {

bool parse_num(const std::string& s, long& out, long lo, long hi) {
  if (s.empty() || s.size() > 9) return false;
  for (char c : s)
    if (c < '0' || c > '9') return false;
  long v = std::strtol(s.c_str(), nullptr, 10);
  if (v < lo || v > hi) return false;
  out = v;
  return true;
}

int fail(const char* cmd, const std::string& msg, int code = 2) {
  fprintf(stderr, "%s: %s\n", cmd, msg.c_str());
  return code;
}

// Linux's own view of a live process: minor/major faults and resident set.
struct LinuxMem { long minflt = -1, majflt = -1, rss_kb = -1; };
LinuxMem linux_mem(pid_t pid) {
  LinuxMem m;
  char path[64], buf[2048];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
  FILE* f = fopen(path, "r");
  if (!f) return m;
  size_t n = fread(buf, 1, sizeof buf - 1, f);
  fclose(f);
  buf[n] = 0;
  char* p = strrchr(buf, ')');
  if (!p) return m;
  // fields after the command: 3 state ... 10 minflt, 12 majflt, 24 rss (pages)
  std::vector<long> v;
  for (char* tok = strtok(p + 2, " "); tok; tok = strtok(nullptr, " ")) v.push_back(atol(tok));
  if (v.size() > 21) {
    m.minflt = v[7];
    m.majflt = v[9];
    m.rss_kb = v[21] * (sysconf(_SC_PAGESIZE) / 1024);
  }
  return m;
}

// ===========================================================================
// mem
// ===========================================================================
void mem_usage() {
  puts("mem - the shell's memory manager.  Processes started by the shell get a paged virtual\n"
       "address space; every load and store goes through the shell, which translates it with the\n"
       "process's page table, handles page faults, and replaces pages when the frames are full.\n"
       "\n"
       "  mem                               configuration, frame table and per-process usage\n"
       "  mem config [-f N] [-p BYTES] [-s PAGES] [-d MS]\n"
       "                                    frames, page size, swap pages, swap I/O time per page\n"
       "  mem policy [fifo|lru|clock]       show or change the page-replacement policy\n"
       "  mem frames                        what every physical frame holds\n"
       "  mem ps [-a]                       memory use of every process (-a: also finished ones)\n"
       "  mem pt PID|%JOB                   the page table of one process\n"
       "  mem stats | mem reset             system totals / reset the counters\n"
       "  mem trace [on|off]                print allocations, faults and evictions as they happen\n"
       "  mem shm [rm NAME]                 shared segments\n"
       "  mem peek NAME [WORD [COUNT]]      read words of a shared segment (no page fault)\n"
       "  mem sim [-a fifo|lru|clock|opt|all] -f N[-M] [-t|-q] REFS\n"
       "                                    replay a reference string offline (textbook table)\n"
       "  REFS: 7,0,1,2,0,3 ('3w' = write) | loop:P:N | rand:N:P:SEED[:W%] | local:N:P:WS:SEED[:W%]\n"
       "\n"
       "  Programs use it through src/mkernel.h; demos/memproc is a test program, e.g.\n"
       "    demos/memproc A 6 7,0,1,2,0,3,0,4 -v     (6 pages, then that reference string)");
}

std::string label_of(Shell& sh, pid_t pid, const std::string& fallback) {
  (void)sh;
  return fallback.empty() ? "pid " + std::to_string((int)pid) : fallback;
}

void print_config(Shell& sh) {
  const MemoryManager& mm = sh.kern.mm;
  printf("Memory: %s\n", describe(mm.config()).c_str());
}

void print_frames(Shell& sh, bool brief) {
  const MemoryManager& mm = sh.kern.mm;
  const auto& fr = mm.frames();
  int used = mm.used_frames();
  std::string bar;
  for (const Frame& f : fr) bar += f.obj < 0 ? '.' : '#';
  if (bar.size() > 64) bar = bar.substr(0, 61) + "...";
  printf("Frames: %d used, %d free  [%s]   committed %ld of %ld pages (RAM + swap), swap slots in use %d\n",
         used, (int)fr.size() - used, bar.c_str(), mm.committed(), (long)mm.config().frames + mm.config().swap_pages,
         mm.swap_used());
  if (brief && used == 0) return;
  // FIFO position and LRU rank for every frame
  std::vector<int> fifo_pos(fr.size(), -1), lru_pos(fr.size(), -1);
  int i = 0;
  for (int f : mm.fifo_order()) fifo_pos[(size_t)f] = ++i;
  i = 0;
  for (int f : mm.lru_order()) lru_pos[(size_t)f] = ++i;
  const char* pol = to_string(mm.config().policy);
  printf("  %-5s %-22s %-6s %5s %5s %4s   (%s evicts %s)\n", "FRAME", "HOLDS", "STATE", "FIFO", "LRU", "REF", pol,
         mm.config().policy == ReplPolicy::FIFO  ? "FIFO position 1 first"
         : mm.config().policy == ReplPolicy::LRU ? "LRU rank 1 first"
                                                 : "the first frame with REF 0 after the hand");
  for (size_t f = 0; f < fr.size(); ++f) {
    const Frame& x = fr[f];
    if (x.obj < 0) {
      if (!brief) printf("  %-5zu %-22s\n", f, "(free)");
      continue;
    }
    bool dirty = false;
    auto it = mm.objects().find(x.obj);
    if (it != mm.objects().end()) dirty = it->second.pages[(size_t)x.idx].dirty;
    std::string holds = mm.owner_label(x.obj, x.idx);
    if (holds.size() > 22) holds = holds.substr(0, 21) + "~";
    printf("  %-5zu %-22s %-6s %5d %5d %4d%s\n", f, holds.c_str(), dirty ? "dirty" : "clean", fifo_pos[f], lru_pos[f],
           x.ref ? 1 : 0, mm.config().policy == ReplPolicy::Clock && (int)f == mm.clock_hand() ? "   <- clock hand" : "");
  }
}

void print_procs(Shell& sh, bool all) {
  const MemoryManager& mm = sh.kern.mm;
  long ps = mm.config().page_size;
  printf("  %-7s %-14s %6s %8s %5s %8s %7s %6s %6s %5s %7s %6s   %s\n", "PID", "NAME", "VPAGES", "RESIDENT", "PEAK",
         "REFS", "FAULTS", "MINOR", "MAJOR", "HIT%", "EVICTED", "WBACK", "LINUX: RSS KB / MINFLT");
  int rows = 0;
  auto row = [&](const ProcMem& p, bool live, const char* tag) {
    double hit = p.st.refs ? 100.0 * (double)p.st.hits / (double)p.st.refs : 0.0;
    std::string name = label_of(sh, p.pid, p.label);
    if (name.size() > 14) name = name.substr(0, 13) + "~";
    int vp = live ? p.vpages() : p.st.peak_vpages;
    int res = live ? mm.resident_of(p) : 0;
    char linux_col[64] = "-";
    if (live) {
      LinuxMem lm = linux_mem(p.pid);
      if (lm.rss_kb >= 0) snprintf(linux_col, sizeof linux_col, "%ld / %ld", lm.rss_kb, lm.minflt);
    } else {
      for (const Job& j : sh.jobs.history())
        if (j.pid == p.pid) snprintf(linux_col, sizeof linux_col, "%ld / %ld (peak)", j.kern_maxrss_kb, j.kern_minflt);
    }
    printf("  %-7d %-14s %6d %8d %5d %8ld %7ld %6ld %6ld %5.1f %7ld %6ld   %s%s\n", (int)p.pid, name.c_str(), vp, res,
           p.st.peak_resident, p.st.refs, p.st.faults, p.st.minor, p.st.major, hit, p.st.evictions, p.st.writebacks,
           linux_col, tag);
    ++rows;
  };
  for (const auto& [pid, p] : mm.procs())
    if (p.vpages() > 0 || p.st.refs > 0) row(p, true, "");
  if (all)
    for (const ProcMem& p : mm.history()) row(p, false, "   (exited)");
  if (!rows) puts("  (no process holds memory)");
  (void)ps;
}

int mem_pt(Shell& sh, const std::string& spec) {
  pid_t pid = 0;
  if (!spec.empty() && spec[0] == '%') {
    std::string err;
    Job* j = sh.resolve_job(spec, err);
    if (!j) return fail("mem pt", err, 1);
    pid = j->pid;
  } else {
    long v;
    if (!parse_num(spec, v, 1, 99999999)) return fail("mem pt", "expected a pid or %JOB, got '" + spec + "'");
    pid = (pid_t)v;
  }
  const MemoryManager& mm = sh.kern.mm;
  const ProcMem* p = mm.proc(pid);
  if (!p) return fail("mem pt", "process " + std::to_string((int)pid) + " has no address space", 1);
  printf("Page table of %s (pid %d): %d virtual page(s), %d resident, page size %ld bytes\n", p->label.c_str(),
         (int)pid, p->vpages(), mm.resident_of(*p), mm.config().page_size);
  printf("  %-6s %-16s %-9s %6s %6s %6s\n", "VPAGE", "MAPS", "STATE", "FRAME", "DIRTY", "SWAP");
  for (size_t v = 0; v < p->pt.size(); ++v) {
    const Pte& e = p->pt[v];
    if (e.obj < 0) { printf("  %-6zu %-16s\n", v, "(invalid: freed)"); continue; }
    auto it = mm.objects().find(e.obj);
    if (it == mm.objects().end()) continue;
    const MemObject& o = it->second;
    const Page& pg = o.pages[(size_t)e.idx];
    std::string maps = o.shared() ? "shm " + o.name + ":" + std::to_string(e.idx) : "private";
    const char* st = pg.st == Page::State::Resident ? "resident" : pg.st == Page::State::Swapped ? "swapped" : "zero";
    printf("  %-6zu %-16s %-9s %6s %6s %6s\n", v, maps.c_str(), st,
           pg.st == Page::State::Resident ? std::to_string(pg.frame).c_str() : "-",
           pg.st == Page::State::Resident ? (pg.dirty ? "yes" : "no") : "-",
           pg.slot >= 0 ? std::to_string(pg.slot).c_str() : "-");
  }
  return 0;
}

void print_totals(Shell& sh) {
  const MemStats& t = sh.kern.mm.total;
  double hit = t.refs ? 100.0 * (double)t.hits / (double)t.refs : 0.0;
  printf("Totals: %ld references, %ld hits (%.1f%%), %ld page faults (%ld minor = zero-fill, %ld major = from swap), "
         "%ld evictions, %ld write-backs to swap; %ld pages allocated, %ld freed\n",
         t.refs, t.hits, hit, t.faults, t.minor, t.major, t.evictions, t.writebacks, t.allocated, t.freed);
}

int mem_config(Shell& sh, const Args& a) {
  MemConfig c = sh.kern.mm.config();
  for (size_t i = 2; i < a.size(); ++i) {
    long v;
    auto need = [&](long lo, long hi, const char* what) {
      if (i + 1 >= a.size()) return fail("mem config", std::string(a[i]) + " needs a value"), false;
      if (!parse_num(a[i + 1], v, lo, hi))
        return fail("mem config", std::string(what) + " must be " + std::to_string(lo) + ".." + std::to_string(hi) +
                                      ", got '" + a[i + 1] + "'"),
               false;
      ++i;
      return true;
    };
    if (a[i] == "-f") { if (!need(1, 4096, "frames")) return 2; c.frames = (int)v; }
    else if (a[i] == "-p") { if (!need(256, 65536, "page size")) return 2; c.page_size = v; }
    else if (a[i] == "-s") { if (!need(0, 65536, "swap pages")) return 2; c.swap_pages = (int)v; }
    else if (a[i] == "-d") { if (!need(0, 1000, "swap I/O time (ms)")) return 2; c.fault_ms = v; }
    else if (a[i] == "-a") {
      if (i + 1 >= a.size() || !parse_policy(a[i + 1], c.policy)) return fail("mem config", "-a needs fifo, lru or clock");
      ++i;
    } else return fail("mem config", "unknown option '" + a[i] + "' (use -f -p -s -d -a)");
  }
  std::string why = sh.kern.mm.configure(c);
  if (!why.empty()) return fail("mem config", why, 1);
  print_config(sh);
  return 0;
}

// ---- mem sim ----------------------------------------------------------------
const char* sim_name(SimPolicy p) {
  switch (p) {
    case SimPolicy::FIFO: return "FIFO";
    case SimPolicy::LRU: return "LRU";
    case SimPolicy::Clock: return "Clock";
    case SimPolicy::OPT: return "OPT";
  }
  return "?";
}

void print_sim_table(const std::vector<int>& refs, const SimResult& r, int nframes) {
  const size_t per = 20;
  int width = 2;
  for (int x : refs) width = std::max(width, (int)std::to_string(x).size() + 1);
  for (size_t b = 0; b < refs.size(); b += per) {
    size_t e = std::min(refs.size(), b + per);
    printf("  %-8s", "ref");
    for (size_t t = b; t < e; ++t) {
      std::string s = std::to_string(refs[t]) + (r.steps[t].write ? "w" : "");
      printf(" %*s", width, s.c_str());
    }
    printf("\n");
    for (int f = 0; f < nframes; ++f) {
      printf("  frame %-2d", f);
      for (size_t t = b; t < e; ++t) {
        int v = r.steps[t].frames[(size_t)f];
        printf(" %*s", width, v < 0 ? "." : std::to_string(v).c_str());
      }
      printf("\n");
    }
    printf("  %-8s", "fault");
    for (size_t t = b; t < e; ++t) printf(" %*s", width, r.steps[t].fault ? "F" : "");
    printf("\n  %-8s", "evicts");
    for (size_t t = b; t < e; ++t)
      printf(" %*s", width, r.steps[t].victim >= 0 ? (std::to_string(r.steps[t].victim) + (r.steps[t].writeback ? "*" : "")).c_str() : "");
    printf("\n\n");
  }
}

int mem_sim(const Args& a) {
  std::vector<SimPolicy> pols;
  long f_lo = 0, f_hi = 0;
  bool table = false, quiet = false;
  std::string spec;
  for (size_t i = 2; i < a.size(); ++i) {
    if (a[i] == "-a") {
      if (i + 1 >= a.size()) return fail("mem sim", "-a needs fifo, lru, clock, opt or all");
      std::string p = a[++i];
      if (p == "all") pols = {SimPolicy::FIFO, SimPolicy::LRU, SimPolicy::Clock, SimPolicy::OPT};
      else if (p == "fifo") pols.push_back(SimPolicy::FIFO);
      else if (p == "lru") pols.push_back(SimPolicy::LRU);
      else if (p == "clock") pols.push_back(SimPolicy::Clock);
      else if (p == "opt") pols.push_back(SimPolicy::OPT);
      else return fail("mem sim", "unknown policy '" + p + "' (fifo, lru, clock, opt, all)");
    } else if (a[i] == "-f") {
      if (i + 1 >= a.size()) return fail("mem sim", "-f needs a frame count, e.g. -f 3 or -f 1-7");
      std::string v = a[++i];
      size_t d = v.find('-');
      bool ok = d == std::string::npos ? parse_num(v, f_lo, 1, 64) && (f_hi = f_lo, true)
                                       : parse_num(v.substr(0, d), f_lo, 1, 64) && parse_num(v.substr(d + 1), f_hi, 1, 64) && f_hi >= f_lo;
      if (!ok) return fail("mem sim", "frames must be 1..64 (or a range like 1-7), got '" + v + "'");
    } else if (a[i] == "-t") table = true;
    else if (a[i] == "-q") quiet = true;
    else if (!a[i].empty() && a[i][0] == '-') return fail("mem sim", "unknown option '" + a[i] + "'");
    else if (spec.empty()) spec = a[i];
    else return fail("mem sim", "only one reference string, got '" + a[i] + "' as well");
  }
  if (spec.empty() || f_lo == 0)
    return fail("mem sim", "usage: mem sim [-a fifo|lru|clock|opt|all] -f N[-M] [-t|-q] REFS");
  if (pols.empty()) pols = {SimPolicy::FIFO, SimPolicy::LRU};
  static int pages[100000];
  static unsigned char writes[100000];
  int n = mk_gen(spec.c_str(), pages, writes, 100000);
  if (n <= 0) return fail("mem sim", "malformed reference string '" + spec + "'");
  std::vector<int> refs(pages, pages + n);
  std::vector<unsigned char> w(writes, writes + n);
  int distinct = (int)std::set<int>(refs.begin(), refs.end()).size();
  printf("Reference string: %d references to %d distinct pages", n, distinct);
  if (n <= 30) {
    printf(" (");
    for (int i = 0; i < n; ++i) printf("%s%d%s", i ? " " : "", refs[(size_t)i], w[(size_t)i] ? "w" : "");
    printf(")");
  }
  printf("\n");
  if (f_lo == f_hi) {
    bool show = table || (!quiet && pols.size() == 1 && n <= 60);
    printf("%ld frame(s)\n", f_lo);
    std::vector<int> faults;
    for (SimPolicy p : pols) {
      SimResult r = simulate(refs, w, (int)f_lo, p);
      if (show) {
        printf("\n%s:\n", sim_name(p));
        print_sim_table(refs, r, (int)f_lo);
      }
      printf("  %-6s %4d page faults  (%d compulsory, %d from replacement)  hit ratio %5.1f%%  evictions %d  "
             "write-backs %d\n",
             sim_name(p), r.faults, std::min(r.faults, distinct), r.faults - std::min(r.faults, distinct),
             100.0 * (n - r.faults) / n, r.evictions, r.writebacks);
    }
    if (show) puts("  (F = page fault; 'evicts' = page replaced, * = it was dirty and written back)");
    return 0;
  }
  // a range of frame counts: faults per policy
  printf("\n  %-7s", "FRAMES");
  for (SimPolicy p : pols) printf(" %7s", sim_name(p));
  printf("\n");
  std::vector<std::vector<int>> res(pols.size());
  for (long f = f_lo; f <= f_hi; ++f) {
    printf("  %-7ld", f);
    for (size_t k = 0; k < pols.size(); ++k) {
      int x = simulate(refs, w, (int)f, pols[k]).faults;
      res[k].push_back(x);
      printf(" %7d", x);
    }
    printf("\n");
  }
  for (size_t k = 0; k < pols.size(); ++k)
    for (size_t i = 1; i < res[k].size(); ++i)
      if (res[k][i] > res[k][i - 1])
        printf("  %s: %ld frames give MORE faults (%d) than %ld frames (%d): Belady's anomaly\n", sim_name(pols[k]),
               f_lo + (long)i, res[k][i], f_lo + (long)i - 1, res[k][i - 1]);
  return 0;
}

}  // namespace

int builtin_mem(Shell& sh, const Args& a) {
  sh.reap_children(false);
  std::string sub = a.size() > 1 ? a[1] : "";
  MemoryManager& mm = sh.kern.mm;
  if (sub.empty() || sub == "status") {
    print_config(sh);
    print_frames(sh, true);
    print_procs(sh, false);
    print_totals(sh);
    return 0;
  }
  if (sub == "help" || sub == "-h" || sub == "--help") { mem_usage(); return 0; }
  if (sub == "config") {
    if (a.size() == 2) { print_config(sh); return 0; }
    return mem_config(sh, a);
  }
  if (sub == "policy") {
    if (a.size() == 2) { printf("page replacement: %s\n", to_string(mm.config().policy)); return 0; }
    ReplPolicy p;
    if (a.size() != 3 || !parse_policy(a[2], p)) return fail("mem policy", "usage: mem policy fifo|lru|clock");
    mm.set_policy(p);
    printf("page replacement: %s (applies to the next eviction)\n", to_string(p));
    return 0;
  }
  if (sub == "frames") { print_frames(sh, false); return 0; }
  if (sub == "ps") {
    if (a.size() > 3 || (a.size() == 3 && a[2] != "-a")) return fail("mem ps", "usage: mem ps [-a]");
    print_procs(sh, a.size() == 3);
    return 0;
  }
  if (sub == "pt") {
    if (a.size() != 3) return fail("mem pt", "usage: mem pt PID|%JOB");
    return mem_pt(sh, a[2]);
  }
  if (sub == "stats") { print_totals(sh); return 0; }
  if (sub == "reset") { mm.reset_stats(); puts("memory statistics reset"); return 0; }
  if (sub == "trace") {
    if (a.size() == 3 && (a[2] == "on" || a[2] == "off")) sh.kern.mem_trace = a[2] == "on";
    else if (a.size() != 2) return fail("mem trace", "usage: mem trace [on|off]");
    printf("memory trace %s (events go to stderr)\n", sh.kern.mem_trace ? "on" : "off");
    return 0;
  }
  if (sub == "shm") {
    if (a.size() == 4 && a[2] == "rm") {
      std::string why;
      if (!mm.shm_remove(a[3], why)) return fail("mem shm", why, 1);
      printf("shared segment '%s' removed\n", a[3].c_str());
      return 0;
    }
    if (a.size() != 2) return fail("mem shm", "usage: mem shm [rm NAME]");
    int n = 0;
    for (const auto& [id, o] : mm.objects()) {
      if (!o.shared()) continue;
      if (!n++) printf("  %-16s %6s %9s %9s\n", "SEGMENT", "PAGES", "RESIDENT", "ATTACHED");
      printf("  %-16s %6zu %9d %9d\n", o.name.c_str(), o.pages.size(), o.resident, o.attached);
    }
    if (!n) puts("(no shared segments)");
    return 0;
  }
  if (sub == "peek") {
    if (a.size() < 3 || a.size() > 5) return fail("mem peek", "usage: mem peek NAME [WORD [COUNT]]");
    long w = 0, cnt = 1;
    if (a.size() > 3 && !parse_num(a[3], w, 0, 10000000)) return fail("mem peek", "bad word index '" + a[3] + "'");
    if (a.size() > 4 && !parse_num(a[4], cnt, 1, 4096)) return fail("mem peek", "bad count '" + a[4] + "'");
    for (long i = 0; i < cnt; ++i) {
      int64_t v;
      if (!mm.shm_peek(a[2], w + i, v)) {
        if (i == 0) return fail("mem peek", "no word " + std::to_string(w + i) + " in shared segment '" + a[2] + "'", 1);
        break;
      }
      printf("%s[%ld] = %lld\n", a[2].c_str(), w + i, (long long)v);
    }
    return 0;
  }
  if (sub == "sim") return mem_sim(a);
  return fail("mem", "unknown subcommand '" + sub + "' (try 'mem help')");
}

// ===========================================================================
// sem
// ===========================================================================
namespace {

void sem_usage() {
  puts("sem - semaphores and mutexes kept by the shell for its processes.  A process that waits\n"
       "(P on a semaphore at 0, or lock on a mutex held by another process) is not answered until\n"
       "it may continue, so it really sleeps and the scheduler runs someone else.  Waiters are woken\n"
       "in FIFO order.  Mutexes have owners: the shell detects wait-for cycles (deadlock) and\n"
       "releases a mutex whose owner exits.\n"
       "\n"
       "  sem                         every semaphore and mutex: value, owner, FIFO queue, statistics\n"
       "  sem create NAME [VALUE]     create a counting semaphore (default 1)\n"
       "  sem create -m NAME          create a mutex\n"
       "  sem post NAME               V() from the prompt (wakes the first waiter)\n"
       "  sem rm NAME | sem reset     remove one / every idle semaphore and mutex\n"
       "  sem clients                 the processes connected to the shell and what they wait for\n"
       "  sem deadlock                look for wait-for cycles now\n"
       "  sem trace [on|off]          print every P/V/lock/unlock as it happens\n"
       "  sem config [--deadlock report|fail] [--handoff fifo|barge]\n"
       "                              on a cycle: report it or refuse the lock (EDEADLK); on V()/unlock:\n"
       "                              hand over to the longest waiter (FIFO) or let everyone compete\n"
       "\n"
       "  Test programs: demos/counter (race condition), demos/pc (producer-consumer),\n"
       "  demos/philo (dining philosophers).");
}

void print_sems(Shell& sh) {
  const auto& objs = sh.kern.sync.objects();
  if (objs.empty()) { puts("(no semaphores or mutexes)"); return; }
  printf("  %-14s %-9s %6s  %-20s %-22s %6s %7s %9s %9s %4s\n", "NAME", "KIND", "VALUE", "OWNER", "WAITERS (FIFO)", "ACQ",
         "WAITED", "AVG-WAIT", "MAX-WAIT", "MAXQ");
  for (const auto& [name, o] : objs) {
    std::string owner = o.is_mutex() ? (o.owner ? sh.kern.label(o.owner) : "-") : "-";
    std::string q;
    for (const SyncWaiter& w : o.waiters) q += (q.empty() ? "" : ",") + std::to_string((int)w.pid);
    if (q.empty()) q = "-";
    if (owner.size() > 20) owner = owner.substr(0, 19) + "~";
    if (q.size() > 22) q = q.substr(0, 21) + "~";
    long done_waits = o.contended - (long)o.waiters.size();   // waits that have finished
    char avg[32], mx[32];
    snprintf(avg, sizeof avg, "%.2f ms", done_waits > 0 ? (double)o.total_wait_us / 1000.0 / (double)done_waits : 0.0);
    snprintf(mx, sizeof mx, "%.1f ms", (double)o.max_wait_us / 1000.0);
    printf("  %-14s %-9s %6s  %-20s %-22s %6ld %7ld %9s %9s %4zu\n", name.c_str(), o.is_mutex() ? "mutex" : "semaphore",
           o.is_mutex() ? (o.owner ? "locked" : "free") : std::to_string(o.value).c_str(), owner.c_str(), q.c_str(),
           o.acquires, o.contended, avg, mx, o.max_queue);
  }
}

}  // namespace

int builtin_sem(Shell& sh, const Args& a) {
  sh.reap_children(false);
  SyncManager& sy = sh.kern.sync;
  std::string sub = a.size() > 1 ? a[1] : "";
  std::string why;
  long now = sh.now_ms();
  if (sub.empty() || sub == "list") { print_sems(sh); return 0; }
  if (sub == "help" || sub == "-h" || sub == "--help") { sem_usage(); return 0; }
  if (sub == "create") {
    bool mutex = a.size() >= 3 && a[2] == "-m";
    size_t ni = mutex ? 3 : 2;
    if (a.size() <= ni || a.size() > ni + (mutex ? 1 : 2)) return fail("sem create", "usage: sem create NAME [VALUE] | sem create -m NAME");
    long v = 1;
    if (!mutex && a.size() == ni + 2 && !parse_num(a[ni + 1], v, 0, 1000000))
      return fail("sem create", "value must be 0..1000000, got '" + a[ni + 1] + "'");
    if (sy.find(a[ni])) return fail("sem create", "'" + a[ni] + "' already exists", 1);
    int s = sy.open(0, a[ni], mutex ? MK_MUTEX : MK_SEMAPHORE, v, false, why);
    if (s < 0) return fail("sem create", why, 1);
    printf("%s '%s' created%s\n", mutex ? "mutex" : "semaphore", a[ni].c_str(),
           mutex ? " (unlocked)" : (" with value " + std::to_string(v)).c_str());
    return 0;
  }
  if (sub == "post") {
    if (a.size() != 3) return fail("sem post", "usage: sem post NAME");
    const SyncObj* o = sy.find(a[2]);
    if (o && o->is_mutex()) return fail("sem post", "'" + a[2] + "' is a mutex: only its owner may unlock it", 1);
    size_t waiting = o ? o->waiters.size() : 0;
    if (sy.post(0, a[2], now, why) < 0) return fail("sem post", why, 1);
    o = sy.find(a[2]);
    if (waiting) printf("V(%s): woke %s\n", a[2].c_str(), "the first waiter");
    else printf("V(%s): value now %ld\n", a[2].c_str(), o ? o->value : 0);
    return 0;
  }
  if (sub == "rm") {
    if (a.size() != 3) return fail("sem rm", "usage: sem rm NAME");
    if (!sy.remove(a[2], why)) return fail("sem rm", why, 1);
    printf("'%s' removed\n", a[2].c_str());
    return 0;
  }
  if (sub == "reset") {
    std::vector<std::string> names;
    for (const auto& [n, o] : sy.objects()) names.push_back(n);
    int removed = 0, kept = 0;
    for (const std::string& n : names) (sy.remove(n, why) ? removed : kept)++;
    printf("%d removed, %d kept (in use)\n", removed, kept);
    return 0;
  }
  if (sub == "clients") {
    auto cl = sh.kern.clients();
    if (cl.empty()) { puts("(no process is connected to the shell's kernel interface)"); return 0; }
    printf("  %-7s %-16s %8s  %s\n", "PID", "NAME", "REQUESTS", "STATE");
    for (const auto& c : cl)
      printf("  %-7d %-16s %8ld  %s\n", (int)c.pid, c.label.c_str(), c.requests,
             c.waiting.empty() ? "running" : ("asleep, waiting for " + c.waiting).c_str());
    return 0;
  }
  if (sub == "deadlock") {
    auto cycles = sy.all_cycles();
    if (cycles.empty()) puts("no wait-for cycle among mutexes right now");
    for (const std::string& c : cycles) printf("DEADLOCK: %s\n", c.c_str());
    printf("deadlocks detected so far: %ld%s%s\n", sy.deadlocks_found, sy.last_deadlock.empty() ? "" : "; last: ",
           sy.last_deadlock.c_str());
    return cycles.empty() ? 0 : 1;
  }
  if (sub == "trace") {
    if (a.size() == 3 && (a[2] == "on" || a[2] == "off")) sh.kern.sync_trace = a[2] == "on";
    else if (a.size() != 2) return fail("sem trace", "usage: sem trace [on|off]");
    printf("synchronization trace %s (events go to stderr)\n", sh.kern.sync_trace ? "on" : "off");
    return 0;
  }
  if (sub == "config") {
    for (size_t i = 2; i < a.size(); i += 2) {
      if (i + 1 < a.size() && a[i] == "--deadlock" && (a[i + 1] == "report" || a[i + 1] == "fail"))
        sy.fail_on_deadlock = a[i + 1] == "fail";
      else if (i + 1 < a.size() && a[i] == "--handoff" && (a[i + 1] == "fifo" || a[i + 1] == "barge"))
        sy.fifo_handoff = a[i + 1] == "fifo";
      else
        return fail("sem config", "usage: sem config [--deadlock report|fail] [--handoff fifo|barge]");
    }
    printf("on a deadlock (mutex wait-for cycle): %s\n",
           sy.fail_on_deadlock ? "refuse the lock that closes the cycle (EDEADLK)" : "report it");
    printf("on V()/unlock with waiters: %s\n",
           sy.fifo_handoff ? "hand it to the longest waiter (FIFO, no starvation)"
                           : "free it and wake the longest waiter to compete again (barging)");
    return 0;
  }
  return fail("sem", "unknown subcommand '" + sub + "' (try 'sem help')");
}
