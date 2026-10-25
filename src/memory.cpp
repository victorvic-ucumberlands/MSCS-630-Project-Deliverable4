// memory.cpp - paging, demand faults, page replacement and swap (see memory.hpp).
#include "memory.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "mkernel.h"

const char* to_string(ReplPolicy p) {
  switch (p) {
    case ReplPolicy::FIFO: return "FIFO";
    case ReplPolicy::LRU: return "LRU";
    case ReplPolicy::Clock: return "Clock";
  }
  return "?";
}

bool parse_policy(const std::string& s, ReplPolicy& out) {
  if (s == "fifo") out = ReplPolicy::FIFO;
  else if (s == "lru") out = ReplPolicy::LRU;
  else if (s == "clock") out = ReplPolicy::Clock;
  else return false;
  return true;
}

std::string describe(const MemConfig& c) {
  return std::to_string(c.frames) + " frames x " + std::to_string(c.page_size) + " bytes (" +
         std::to_string((long)c.frames * c.page_size / 1024) + " KB), swap " + std::to_string(c.swap_pages) +
         " pages, replacement " + to_string(c.policy) + ", swap I/O " + std::to_string(c.fault_ms) + " ms";
}

long MemObject::committed() const {
  long n = 0;
  for (const Page& p : pages) n += p.st != Page::State::Unused;
  return n;
}

int ProcMem::vpages() const {
  int n = 0;
  for (const Pte& e : pt) n += e.obj >= 0;
  return n;
}

// ===========================================================================
// Configuration
// ===========================================================================
std::string MemoryManager::configure(const MemConfig& c) {
  if (c.frames < 1 || c.frames > 4096) return "frames must be 1..4096";
  if (c.page_size < 256 || c.page_size > 65536 || (c.page_size & (c.page_size - 1)))
    return "page size must be a power of two from 256 to 65536 bytes";
  if (c.swap_pages < 0 || c.swap_pages > 65536) return "swap must be 0..65536 pages";
  if (c.fault_ms < 0 || c.fault_ms > 1000) return "swap I/O time must be 0..1000 ms";
  bool geometry = c.frames != cfg_.frames || c.page_size != cfg_.page_size || c.swap_pages != cfg_.swap_pages;
  if (geometry && (committed() > 0 || !procs_.empty()))
    return "memory is in use; frames, page size and swap can only change when no process holds memory "
           "(and no shared segment exists)";
  if (geometry) {
    cfg_ = c;
    ram_.assign((size_t)c.frames * (size_t)c.page_size, 0);
    frames_.assign((size_t)c.frames, Frame{});
    free_.clear();
    for (int i = 0; i < c.frames; ++i) free_.insert(i);
    fifo_.clear();
    lru_.clear();
    fifo_it_.assign((size_t)c.frames, {});
    lru_it_.assign((size_t)c.frames, {});
    hand_ = 0;
    swap_.clear();
    free_slots_.clear();
    slots_used_ = 0;
  }
  cfg_ = c;
  return "";
}

void MemoryManager::set_policy(ReplPolicy p) { cfg_.policy = p; }

void MemoryManager::reset_stats() {
  total = MemStats{};
  for (auto& [pid, p] : procs_) {
    p.st = MemStats{};
    p.st.peak_resident = resident_of(p);
    p.st.peak_vpages = p.vpages();
  }
  history_.clear();
}

long MemoryManager::committed() const {
  long n = 0;
  for (const auto& [id, o] : objs_) n += o.committed();
  return n;
}

int MemoryManager::resident_of(const ProcMem& p) const {
  int n = 0;
  for (const Pte& e : p.pt) {
    if (e.obj < 0) continue;
    auto it = objs_.find(e.obj);
    if (it != objs_.end() && it->second.pages[(size_t)e.idx].st == Page::State::Resident) ++n;
  }
  return n;
}

const ProcMem* MemoryManager::proc(pid_t pid) const {
  auto it = procs_.find(pid);
  return it == procs_.end() ? nullptr : &it->second;
}

ProcMem* MemoryManager::find(pid_t pid) {
  auto it = procs_.find(pid);
  return it == procs_.end() ? nullptr : &it->second;
}

std::string MemoryManager::owner_label(int obj, int idx) const {
  auto it = objs_.find(obj);
  if (it == objs_.end()) return "?";
  const MemObject& o = it->second;
  if (o.shared()) return "shm " + o.name + ":" + std::to_string(idx);
  // the virtual page of the owner that maps this object page
  auto p = procs_.find(o.owner);
  long vp = idx;
  if (p != procs_.end())
    for (size_t i = 0; i < p->second.pt.size(); ++i)
      if (p->second.pt[i].obj == obj && p->second.pt[i].idx == idx) { vp = (long)i; break; }
  std::string who = p != procs_.end() ? p->second.label : ("pid " + std::to_string((int)o.owner));
  return who + ":" + std::to_string(vp);
}

int MemoryManager::new_object(const std::string& name, pid_t owner) {
  int id = next_obj_++;
  MemObject& o = objs_[id];
  o.id = id;
  o.name = name;
  o.owner = owner;
  return id;
}

// ===========================================================================
// Address spaces
// ===========================================================================
ProcMem& MemoryManager::attach(pid_t pid, const std::string& label, long now_ms) {
  ProcMem& p = procs_[pid];
  if (p.pid == 0) {
    p.pid = pid;
    p.label = label;
    p.start_ms = now_ms;
    p.private_obj = new_object("", pid);
  } else if (!label.empty()) {
    p.label = label;
  }
  return p;
}

long MemoryManager::alloc(pid_t pid, long n, std::string& why) {
  ProcMem* p = find(pid);
  if (!p) { why = "process has no address space"; return -EINVAL; }
  if (n < 1 || n > 65536) { why = "page count must be 1..65536"; return -EINVAL; }
  if ((long)p->pt.size() + n > 65536) { why = "address space limit is 65536 pages"; return -ENOMEM; }
  long avail = (long)cfg_.frames + cfg_.swap_pages - committed();
  if (n > avail) {
    why = "out of memory: " + std::to_string(n) + " pages requested, " + std::to_string(std::max(0L, avail)) +
          " available in RAM + swap (" + std::to_string(cfg_.frames) + " frames + " +
          std::to_string(cfg_.swap_pages) + " swap pages)";
    return -ENOMEM;
  }
  MemObject& o = objs_[p->private_obj];
  long first = (long)p->pt.size();
  for (long i = 0; i < n; ++i) {
    o.pages.push_back(Page{Page::State::Zero, -1, false, -1});
    p->pt.push_back(Pte{o.id, (int)o.pages.size() - 1});
  }
  p->st.allocated += n;
  total.allocated += n;
  p->st.peak_vpages = std::max(p->st.peak_vpages, p->vpages());
  emit("ALLOC", p->label + ": " + std::to_string(n) + " page(s) allocated, virtual pages " + std::to_string(first) +
                    "-" + std::to_string(first + n - 1) + " (not yet in memory: demand paging)");
  return first;
}

void MemoryManager::release_page(MemObject& o, int idx) {
  Page& pg = o.pages[(size_t)idx];
  if (pg.st == Page::State::Resident) {
    int f = pg.frame;
    fifo_.erase(fifo_it_[(size_t)f]);
    lru_.erase(lru_it_[(size_t)f]);
    frames_[(size_t)f] = Frame{};
    free_.insert(f);
    o.resident--;
    if ((int)free_.size() == cfg_.frames) hand_ = 0;   // memory empty again: the clock hand starts over
  }
  if (pg.slot >= 0) {
    swap_[(size_t)pg.slot].clear();
    swap_[(size_t)pg.slot].shrink_to_fit();
    free_slots_.push_back(pg.slot);
    slots_used_--;
  }
  pg = Page{};
}

int MemoryManager::release(pid_t pid, long first, long n, std::string& why) {
  ProcMem* p = find(pid);
  if (!p) { why = "process has no address space"; return -EINVAL; }
  if (n < 1 || first < 0 || first + n > (long)p->pt.size()) { why = "range is outside the address space"; return -EINVAL; }
  for (long v = first; v < first + n; ++v)
    if (p->pt[(size_t)v].obj != p->private_obj) {
      why = "virtual page " + std::to_string(v) + " is not allocated private memory";
      return -EINVAL;
    }
  MemObject& o = objs_[p->private_obj];
  int freed_frames = 0;
  for (long v = first; v < first + n; ++v) {
    Pte& e = p->pt[(size_t)v];
    freed_frames += o.pages[(size_t)e.idx].st == Page::State::Resident;
    release_page(o, e.idx);
    e = Pte{};
  }
  p->st.freed += n;
  total.freed += n;
  emit("FREE", p->label + ": virtual pages " + std::to_string(first) + "-" + std::to_string(first + n - 1) +
                   " freed (" + std::to_string(freed_frames) + " frame(s) returned to the free list)");
  return 0;
}

long MemoryManager::shm_attach(pid_t pid, const std::string& name, long n, std::string& why) {
  ProcMem* p = find(pid);
  if (!p) { why = "process has no address space"; return -EINVAL; }
  if (name.empty()) { why = "a shared segment needs a name"; return -EINVAL; }
  MemObject* o = nullptr;
  for (auto& [id, obj] : objs_)
    if (obj.shared() && obj.name == name) o = &obj;
  if (!o) {
    if (n < 1 || n > 4096) { why = "shared segment '" + name + "' does not exist (create it with 1..4096 pages)"; return -ENOENT; }
    long avail = (long)cfg_.frames + cfg_.swap_pages - committed();
    if (n > avail) { why = "out of memory for shared segment"; return -ENOMEM; }
    o = &objs_[new_object(name, 0)];
    o->pages.assign((size_t)n, Page{Page::State::Zero, -1, false, -1});
    emit("SHM", "shared segment '" + name + "' created with " + std::to_string(n) + " page(s)");
  } else if (n > (long)o->pages.size()) {
    why = "shared segment '" + name + "' has only " + std::to_string(o->pages.size()) + " page(s)";
    return -EINVAL;
  }
  if (std::find(p->shm.begin(), p->shm.end(), o->id) != p->shm.end()) {
    for (size_t i = 0; i < p->pt.size(); ++i)                       // already mapped: same address
      if (p->pt[i].obj == o->id && p->pt[i].idx == 0) return (long)i;
  }
  long first = (long)p->pt.size();
  if (first + (long)o->pages.size() > 65536) { why = "address space limit is 65536 pages"; return -ENOMEM; }
  for (size_t i = 0; i < o->pages.size(); ++i) p->pt.push_back(Pte{o->id, (int)i});
  p->shm.push_back(o->id);
  o->attached++;
  p->st.peak_vpages = std::max(p->st.peak_vpages, p->vpages());
  emit("SHM", p->label + ": attached shared segment '" + name + "' at virtual pages " + std::to_string(first) + "-" +
                  std::to_string(first + (long)o->pages.size() - 1));
  return first;
}

void MemoryManager::detach(pid_t pid, long now_ms) {
  ProcMem* p = find(pid);
  if (!p) return;
  int frames_back = 0;
  long pages = 0;
  auto it = objs_.find(p->private_obj);
  if (it != objs_.end()) {
    MemObject& o = it->second;
    for (size_t i = 0; i < o.pages.size(); ++i) {
      if (o.pages[i].st == Page::State::Unused) continue;
      ++pages;
      frames_back += o.pages[i].st == Page::State::Resident;
      release_page(o, (int)i);
    }
    objs_.erase(it);
  }
  for (int id : p->shm) {
    auto s = objs_.find(id);
    if (s != objs_.end()) s->second.attached--;
  }
  p->end_ms = now_ms;
  if (pages > 0 || p->st.refs > 0 || !p->shm.empty())
    emit("EXIT", p->label + ": address space released, " + std::to_string(pages) + " page(s) and " +
                     std::to_string(frames_back) + " frame(s) freed");
  p->pt.clear();
  p->pt.shrink_to_fit();
  if (p->st.allocated > 0 || p->st.refs > 0 || !p->shm.empty()) {
    history_.push_back(*p);
    if (history_.size() > 256) history_.erase(history_.begin());
  }
  procs_.erase(pid);
}

bool MemoryManager::shm_remove(const std::string& name, std::string& why) {
  for (auto it = objs_.begin(); it != objs_.end(); ++it) {
    MemObject& o = it->second;
    if (!o.shared() || o.name != name) continue;
    if (o.attached > 0) { why = "segment '" + name + "' is still attached by " + std::to_string(o.attached) + " process(es)"; return false; }
    for (size_t i = 0; i < o.pages.size(); ++i) release_page(o, (int)i);
    objs_.erase(it);
    return true;
  }
  why = "no shared segment '" + name + "'";
  return false;
}

bool MemoryManager::shm_peek(const std::string& name, long word, int64_t& out) {
  for (auto& [id, o] : objs_) {
    if (!o.shared() || o.name != name) continue;
    long per = cfg_.page_size / MK_WORD;
    long idx = word / per, off = (word % per) * MK_WORD;
    if (word < 0 || idx >= (long)o.pages.size()) return false;
    const Page& pg = o.pages[(size_t)idx];
    out = 0;
    if (pg.st == Page::State::Resident) memcpy(&out, frame_data(pg.frame) + off, sizeof out);
    else if (pg.st == Page::State::Swapped) memcpy(&out, swap_[(size_t)pg.slot].data() + off, sizeof out);
    return true;
  }
  return false;
}

void MemoryManager::clear_all() {
  objs_.clear();
  procs_.clear();
  history_.clear();
  const MemConfig& c = cfg_;
  ram_.assign((size_t)c.frames * (size_t)c.page_size, 0);
  frames_.assign((size_t)c.frames, Frame{});
  free_.clear();
  for (int i = 0; i < c.frames; ++i) free_.insert(i);
  fifo_.clear();
  lru_.clear();
  fifo_it_.assign((size_t)c.frames, {});
  lru_it_.assign((size_t)c.frames, {});
  hand_ = 0;
  swap_.clear();
  free_slots_.clear();
  slots_used_ = 0;
  total = MemStats{};
}

void MemoryManager::bump_peaks(const MemObject& o) {
  if (!o.shared()) {
    if (ProcMem* p = find(o.owner)) p->st.peak_resident = std::max(p->st.peak_resident, resident_of(*p));
    return;
  }
  for (auto& [pid, p] : procs_)
    if (std::find(p.shm.begin(), p.shm.end(), o.id) != p.shm.end())
      p.st.peak_resident = std::max(p.st.peak_resident, resident_of(p));
}

// ===========================================================================
// Replacement
// ===========================================================================
int MemoryManager::pick_victim(long now) {
  switch (cfg_.policy) {
    case ReplPolicy::FIFO:                          // oldest load first
      for (int f : fifo_)
        if (frames_[(size_t)f].pinned_until <= now) return f;
      return -1;
    case ReplPolicy::LRU:                           // least recently referenced first
      for (int f : lru_)
        if (frames_[(size_t)f].pinned_until <= now) return f;
      return -1;
    case ReplPolicy::Clock: {                       // second chance: clear reference bits as the hand passes
      int n = cfg_.frames;
      for (int step = 0; step < 2 * n + 1; ++step) {
        int f = hand_;
        hand_ = (hand_ + 1) % n;
        Frame& fr = frames_[(size_t)f];
        if (fr.obj < 0 || fr.pinned_until > now) continue;
        if (fr.ref) { fr.ref = false; continue; }
        return f;
      }
      return -1;
    }
  }
  return -1;
}

// A swap slot for an evicted page.  When every slot is taken, a copy kept by a
// RESIDENT page is reclaimed (that page becomes dirty, so it will be written
// again if it is evicted).  Memory is committed at allocation, so if that
// fails too the only copies left belong to pages out of memory - among them
// the page being faulted in, whose slot is then reused (took_own = true).
int MemoryManager::take_slot(int keep_obj, int keep_idx, bool& took_own) {
  took_own = false;
  if (!free_slots_.empty()) {
    int s = free_slots_.back();
    free_slots_.pop_back();
    slots_used_++;
    return s;
  }
  if ((int)swap_.size() < cfg_.swap_pages) {
    swap_.emplace_back();
    slots_used_++;
    return (int)swap_.size() - 1;
  }
  for (auto& [id, o] : objs_)
    for (Page& pg : o.pages)
      if (pg.st == Page::State::Resident && pg.slot >= 0) {
        int s = pg.slot;
        pg.slot = -1;
        pg.dirty = true;
        return s;
      }
  auto it = objs_.find(keep_obj);
  if (it != objs_.end()) {
    Page& pg = it->second.pages[(size_t)keep_idx];
    if (pg.slot >= 0) {
      int s = pg.slot;
      pg.slot = -1;
      took_own = true;
      return s;
    }
  }
  return -1;
}

// ===========================================================================
// One memory reference: translation, page fault, replacement, the access
// ===========================================================================
Access MemoryManager::access(pid_t pid, int64_t vaddr, bool write, int64_t value, long now) {
  Access a;
  ProcMem* p = find(pid);
  if (!p) { a.status = -EFAULT; return a; }
  if (vaddr < 0 || vaddr % MK_WORD) { a.status = -EINVAL; return a; }
  long vpage = (long)(vaddr / cfg_.page_size);
  long off = (long)(vaddr % cfg_.page_size);
  if (vpage >= (long)p->pt.size() || p->pt[(size_t)vpage].obj < 0) {
    a.status = -EFAULT;                              // not mapped: segmentation fault
    emit("SEGV", p->label + ": " + (write ? "write to" : "read of") + " virtual page " + std::to_string(vpage) +
                     " (address " + std::to_string((long long)vaddr) + "), which is not allocated: SIGSEGV");
    return a;
  }
  Pte e = p->pt[(size_t)vpage];
  MemObject& o = objs_[e.obj];
  const std::string where = p->label + " page " + std::to_string(vpage);
  ++tick_;
  p->st.refs++;
  total.refs++;

  if (o.pages[(size_t)e.idx].st != Page::State::Resident) {
    // ---- page fault ------------------------------------------------------
    int f = -1;
    if (!free_.empty()) {
      f = *free_.begin();
    } else {
      f = pick_victim(now);
      if (f < 0) {                                   // every frame is busy with I/O
        p->st.refs--;
        total.refs--;
        --tick_;
        a.retry = true;
        return a;
      }
    }
    Page& pg = o.pages[(size_t)e.idx];
    const bool major = pg.st == Page::State::Swapped;
    std::vector<uint8_t> incoming;
    if (major) incoming = swap_[(size_t)pg.slot];    // read before its slot can be reused
    long io = 0;

    Frame& fr = frames_[(size_t)f];
    if (fr.obj >= 0) {
      // ---- evict the victim ----------------------------------------------
      MemObject& vo = objs_[fr.obj];
      Page& vp = vo.pages[(size_t)fr.idx];
      a.flags |= MKF_EVICT;
      a.victim_label = owner_label(fr.obj, fr.idx);
      a.victim_pid = vo.owner;
      a.victim_page = fr.idx;
      if (!vo.shared())
        if (ProcMem* vpm = find(vo.owner))
          for (size_t i = 0; i < vpm->pt.size(); ++i)
            if (vpm->pt[i].obj == fr.obj && vpm->pt[i].idx == fr.idx) { a.victim_page = (long)i; break; }
      std::string how;
      if (vp.dirty) {
        bool took_own = false;
        if (vp.slot < 0) vp.slot = take_slot(e.obj, e.idx, took_own);
        if (vp.slot < 0) {                           // cannot happen: memory is committed at allocation
          a.status = -ENOMEM;
          return a;
        }
        if (took_own) pg.slot = -1;
        swap_[(size_t)vp.slot].assign(frame_data(f), frame_data(f) + cfg_.page_size);
        vp.st = Page::State::Swapped;
        a.flags |= MKF_WRITEBACK;
        io += cfg_.fault_ms;
        total.writebacks++;
        if (!vo.shared())
          if (ProcMem* vpm = find(vo.owner)) vpm->st.writebacks++;
        how = "dirty, written to swap slot " + std::to_string(vp.slot);
      } else if (vp.slot >= 0) {
        vp.st = Page::State::Swapped;                // clean: the swap copy is still valid
        how = "clean, its copy in swap slot " + std::to_string(vp.slot) + " is still valid";
      } else {
        vp.st = Page::State::Zero;                   // never written: nothing to save
        how = "clean, never written: dropped";
      }
      vp.frame = -1;
      vp.dirty = false;
      vo.resident--;
      total.evictions++;
      if (!vo.shared())
        if (ProcMem* vpm = find(vo.owner)) vpm->st.evictions++;
      fifo_.erase(fifo_it_[(size_t)f]);
      lru_.erase(lru_it_[(size_t)f]);
      emit("EVICT", "frame " + std::to_string(f) + ": " + a.victim_label + " evicted by " + to_string(cfg_.policy) +
                        " (" + how + ")");
    } else {
      free_.erase(f);
    }

    // ---- load the page -----------------------------------------------------
    uint8_t* d = frame_data(f);
    if (major) {
      memcpy(d, incoming.data(), (size_t)cfg_.page_size);
      a.flags |= MKF_MAJOR;
      io += cfg_.fault_ms;
      p->st.major++;
      total.major++;
    } else {
      memset(d, 0, (size_t)cfg_.page_size);
      p->st.minor++;
      total.minor++;
    }
    pg.st = Page::State::Resident;
    pg.frame = f;
    pg.dirty = pg.slot < 0 && major;                 // its only copy is now in memory
    fr = Frame{e.obj, e.idx, tick_, tick_, true, 0};
    fifo_.push_back(f);
    fifo_it_[(size_t)f] = std::prev(fifo_.end());
    lru_.push_back(f);
    lru_it_[(size_t)f] = std::prev(lru_.end());
    o.resident++;
    a.flags |= MKF_FAULT;
    p->st.faults++;
    total.faults++;
    if (io > 0) {
      // One swap device serving one transfer at a time: a fault that finds it
      // busy waits in its queue.  This is what makes thrashing collapse:
      // the device, not the CPU, becomes the bottleneck.
      long start = std::max(now, disk_free_at_);
      disk_free_at_ = start + io;
      fr.pinned_until = disk_free_at_;
      a.ready_at = disk_free_at_;
      total.io_wait_ms += disk_free_at_ - now;
      if (start > now) io_text_queue_ = " (queued " + std::to_string(start - now) + " ms behind other swap I/O)";
      else io_text_queue_.clear();
    }
    bump_peaks(o);
    std::string io_text;
    if (io > 0)
      io_text = std::string(" (") + ((a.flags & MKF_WRITEBACK) && major ? "write-back + read" : (a.flags & MKF_WRITEBACK) ? "write-back of the victim" : "read") +
                ": " + std::to_string(io) + " ms of swap I/O, the process sleeps)" + io_text_queue_;
    emit("FAULT", where + ": not in memory -> " + (major ? "MAJOR fault, read from swap" : "minor fault, zero-filled") +
                     " into frame " + std::to_string(f) + io_text);
  } else {
    p->st.hits++;
    total.hits++;
    Frame& fr = frames_[(size_t)o.pages[(size_t)e.idx].frame];
    if (fr.pinned_until > now) a.ready_at = fr.pinned_until;   // still being read in for someone else
  }

  // ---- the access itself -------------------------------------------------
  Page& pg = o.pages[(size_t)e.idx];
  int f = pg.frame;
  Frame& fr = frames_[(size_t)f];
  fr.last_use = tick_;
  fr.ref = true;
  lru_.splice(lru_.end(), lru_, lru_it_[(size_t)f]);  // most recently used goes to the back
  uint8_t* d = frame_data(f) + off;
  if (write) {
    memcpy(d, &value, sizeof value);
    pg.dirty = true;
  } else {
    memcpy(&a.value, d, sizeof a.value);
  }
  a.frame = f;
  return a;
}

// ===========================================================================
// Offline simulation (textbook tables)
// ===========================================================================
SimResult simulate(const std::vector<int>& refs, const std::vector<unsigned char>& writes, int nframes,
                   SimPolicy policy) {
  SimResult r;
  std::vector<int> page(nframes, -1);
  std::vector<long> loaded(nframes, 0), used(nframes, 0);
  std::vector<bool> refbit(nframes, false), dirty(nframes, false);
  int hand = 0;
  for (size_t t = 0; t < refs.size(); ++t) {
    SimStep s;
    s.ref = refs[t];
    s.write = t < writes.size() && writes[t];
    int at = -1;
    for (int f = 0; f < nframes; ++f)
      if (page[f] == s.ref) at = f;
    if (at < 0) {
      s.fault = true;
      r.faults++;
      for (int f = 0; f < nframes && at < 0; ++f)
        if (page[f] < 0) at = f;                   // a free frame, lowest first
      if (at < 0) {
        switch (policy) {
          case SimPolicy::FIFO:
            at = 0;
            for (int f = 1; f < nframes; ++f) if (loaded[f] < loaded[at]) at = f;
            break;
          case SimPolicy::LRU:
            at = 0;
            for (int f = 1; f < nframes; ++f) if (used[f] < used[at]) at = f;
            break;
          case SimPolicy::Clock:
            for (;;) {
              int f = hand;
              hand = (hand + 1) % nframes;
              if (refbit[f]) { refbit[f] = false; continue; }
              at = f;
              break;
            }
            break;
          case SimPolicy::OPT: {                   // the page used furthest in the future
            long best = -1;
            for (int f = 0; f < nframes; ++f) {
              long next = (long)refs.size() + (nframes - f);   // never used again: prefer it (lowest frame first)
              for (size_t u = t + 1; u < refs.size(); ++u)
                if (refs[u] == page[f]) { next = (long)u; break; }
              if (next > best) { best = next; at = f; }
            }
            break;
          }
        }
        s.victim = page[at];
        s.writeback = dirty[at];
        r.evictions++;
        r.writebacks += dirty[at];
      }
      page[at] = s.ref;
      loaded[at] = (long)t + 1;
      dirty[at] = false;
    }
    used[at] = (long)t + 1;
    refbit[at] = true;
    if (s.write) dirty[at] = true;
    s.frames = page;
    r.steps.push_back(s);
  }
  return r;
}
