// memory.hpp - the shell's memory manager: paging with fixed-size frames,
// demand paging, page replacement (FIFO / LRU / Clock) and a swap area
// (Deliverable 3).
//
// Physical memory is an array of `frames` page frames of `page_size` bytes
// that the shell owns.  Every process that uses the shell's memory has a
// virtual address space described by a page table: virtual page -> (memory
// object, page of that object).  A memory object is either the private
// memory of one process or a named shared segment that several processes map,
// so a shared page lives in ONE frame however many page tables point at it.
//
// A page is in one of four states:
//   Unused    not allocated;
//   Zero      allocated but never stored to swap: its contents are all zero, so
//             the first touch is a MINOR fault (zero-fill, no "disk" I/O);
//   Resident  in a physical frame;
//   Swapped   evicted; its contents are in a swap slot, so touching it again
//             is a MAJOR fault (read back from swap).
//
// When a fault finds no free frame the replacement policy picks a victim
// frame.  A dirty victim is written to swap first (write-back); a clean one
// whose swap copy is still valid, or one that was never written, is simply
// dropped.  The policies are global: the victim may belong to any process.
//
// Memory is committed when it is allocated: an allocation is refused with
// ENOMEM if resident memory plus swap could not hold every allocated page.
// Overflow of physical memory is therefore always handled by paging, never by
// killing a process.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

enum class ReplPolicy { FIFO, LRU, Clock };
const char* to_string(ReplPolicy p);
bool parse_policy(const std::string& s, ReplPolicy& out);

struct MemConfig {
  int frames = 16;              // physical page frames
  long page_size = 4096;        // bytes per page (power of two, 256..65536)
  int swap_pages = 64;          // swap slots (backing store)
  long fault_ms = 0;            // time to read/write a page from/to swap ("disk" latency)
  ReplPolicy policy = ReplPolicy::LRU;
};
std::string describe(const MemConfig& c);

struct Page {
  enum class State { Unused, Zero, Resident, Swapped } st = State::Unused;
  int frame = -1;               // valid when Resident
  bool dirty = false;           // written since it was loaded (Resident only)
  int slot = -1;                // swap slot holding a copy (-1 = none)
};

struct MemObject {
  int id = 0;
  std::string name;             // "" = private memory of `owner`
  pid_t owner = 0;              // 0 for a shared segment
  std::vector<Page> pages;
  int attached = 0;             // page tables mapping it (shared segments)
  int resident = 0;
  long committed() const;       // allocated pages
  bool shared() const { return owner == 0; }
};

struct Pte {
  int obj = -1;                 // -1 = invalid (unallocated or freed)
  int idx = -1;
};

struct MemStats {
  long refs = 0, hits = 0, faults = 0, minor = 0, major = 0;
  long evictions = 0;           // pages of this process evicted (stolen) by anyone
  long writebacks = 0;          // dirty pages of this process written to swap
  long allocated = 0, freed = 0;    // pages
  int peak_resident = 0;        // most frames it held at once (its pages incl. shared)
  int peak_vpages = 0;
  long io_wait_ms = 0;          // time faults spent waiting for the swap device (system total)
};

struct ProcMem {
  pid_t pid = 0;
  std::string label;
  int private_obj = -1;
  std::vector<Pte> pt;          // the page table, indexed by virtual page
  std::vector<int> shm;         // shared segments it attached
  MemStats st;
  long start_ms = 0, end_ms = 0;
  int vpages() const;           // valid entries in the page table
};

struct Frame {
  int obj = -1, idx = -1;       // the page it holds (-1 = free)
  long loaded = 0;              // load order (FIFO)
  long last_use = 0;            // reference order (LRU)
  bool ref = false;             // reference bit (Clock)
  long pinned_until = 0;        // page I/O in progress until this time (ms)
};

// Result of one memory reference.
struct Access {
  int status = 0;               // 0, -EFAULT (segmentation fault), -EINVAL
  uint32_t flags = 0;           // MKF_* from mkernel.h
  int64_t value = 0;            // the word read
  int frame = -1;
  pid_t victim_pid = -1;        // owner of the evicted page (0 = shared segment)
  long victim_page = -1;
  std::string victim_label;
  long ready_at = 0;            // the access completes at this time (0 = now)
  bool retry = false;           // every frame is busy with I/O: try again later
};

class MemoryManager {
 public:
  // Event log: kind ("FAULT", "EVICT", "ALLOC", ...) and a one-line detail.
  std::function<void(const char* kind, const std::string& detail)> log;

  std::string configure(const MemConfig& c);   // "" or the reason it was refused
  const MemConfig& config() const { return cfg_; }
  void set_policy(ReplPolicy p);
  void reset_stats();

  // ---- requests from processes -----------------------------------------
  ProcMem& attach(pid_t pid, const std::string& label, long now_ms);   // on connect
  void detach(pid_t pid, long now_ms);                                 // on exit: free everything
  long alloc(pid_t pid, long npages, std::string& why);                // first page or -errno
  int  release(pid_t pid, long first, long npages, std::string& why);  // 0 or -errno
  long shm_attach(pid_t pid, const std::string& name, long npages, std::string& why);
  Access access(pid_t pid, int64_t vaddr, bool write, int64_t value, long now_ms);

  // ---- shell-side operations -------------------------------------------
  bool shm_remove(const std::string& name, std::string& why);
  bool shm_peek(const std::string& name, long word, int64_t& out);     // read without faulting
  void clear_all();                          // forget every process and segment (in a forked child)

  // ---- inspection --------------------------------------------------------
  const std::vector<Frame>& frames() const { return frames_; }
  const std::map<int, MemObject>& objects() const { return objs_; }
  const std::map<pid_t, ProcMem>& procs() const { return procs_; }
  const std::vector<ProcMem>& history() const { return history_; }
  const ProcMem* proc(pid_t pid) const;
  std::string owner_label(int obj, int idx) const;   // "A:3" or "shm buf:0"
  int used_frames() const { return cfg_.frames - (int)free_.size(); }
  long committed() const;
  int swap_used() const { return (int)slots_used_; }
  int resident_of(const ProcMem& p) const;
  std::vector<int> fifo_order() const { return {fifo_.begin(), fifo_.end()}; }
  std::vector<int> lru_order() const { return {lru_.begin(), lru_.end()}; }
  int clock_hand() const { return hand_; }

  MemStats total;                            // the whole system since the last reset
  long seq() const { return tick_; }

 private:
  ProcMem* find(pid_t pid);
  int new_object(const std::string& name, pid_t owner);
  void release_page(MemObject& o, int idx);
  int pick_victim(long now);
  int take_slot(int keep_obj, int keep_idx, bool& took_own);
  void bump_peaks(const MemObject& o);
  void emit(const char* kind, const std::string& d) { if (log) log(kind, d); }
  uint8_t* frame_data(int f) { return &ram_[(size_t)f * (size_t)cfg_.page_size]; }

  MemConfig cfg_;
  std::vector<uint8_t> ram_ = std::vector<uint8_t>((size_t)16 * 4096);
  std::vector<Frame> frames_ = std::vector<Frame>(16);
  std::set<int> free_ = [] { std::set<int> s; for (int i = 0; i < 16; ++i) s.insert(i); return s; }();
  std::list<int> fifo_, lru_;
  std::vector<std::list<int>::iterator> fifo_it_ = std::vector<std::list<int>::iterator>(16);
  std::vector<std::list<int>::iterator> lru_it_ = std::vector<std::list<int>::iterator>(16);
  int hand_ = 0;
  std::vector<std::vector<uint8_t>> swap_;   // swap slots (allocated lazily)
  std::vector<int> free_slots_;
  size_t slots_used_ = 0;
  std::map<int, MemObject> objs_;
  std::map<pid_t, ProcMem> procs_;
  std::vector<ProcMem> history_;
  int next_obj_ = 1;
  long tick_ = 0;                            // reference counter (LRU / FIFO order)
  long disk_free_at_ = 0;                    // the swap device is busy until then (one page at a time)
  std::string io_text_queue_;
};

// ---------------------------------------------------------------------------
// Offline simulation of one reference string (`mem sim`): the textbook view,
// with Belady's optimal algorithm as a baseline.  Deliberately independent of
// MemoryManager so the two can be checked against each other.
// ---------------------------------------------------------------------------
enum class SimPolicy { FIFO, LRU, Clock, OPT };
struct SimStep {
  int ref = 0;
  bool write = false;
  bool fault = false;
  int victim = -1;              // page evicted (-1 = none)
  bool writeback = false;
  std::vector<int> frames;      // contents after the reference (-1 = empty)
};
struct SimResult {
  std::vector<SimStep> steps;
  int faults = 0, evictions = 0, writebacks = 0;
};
SimResult simulate(const std::vector<int>& refs, const std::vector<unsigned char>& writes, int frames,
                   SimPolicy p);
