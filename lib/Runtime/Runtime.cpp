/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <atomic>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)

extern "C"  {
__attribute__((noinline))
void break_here(void) {
  asm("nop");
}
}

#define debug_write(...)

inline namespace __rsan {

using Watchpoint = std::atomic<uint8_t>;

enum : size_t {

  // Size of the shadow memory (1 GiB).
  kShadowSize = 1073741824,
  kShadowMask = 1073741824 - 1,

  // Number of watchpoints that fit into shadow memory.
  kNumWatchpoints = kShadowSize / sizeof(Watchpoint),

  // Granularity, in bytes, of shadow memory. For example, if the granularity
  // is 16 bytes, then 16 bytes of normal memory maps to one unit of shadow
  // memory.
  kGranularity = 8,

  // Size, in bytes, of a cache line.
  kCacheLineSize = 64,
  kCacheLineShift = 6,

  // The amount of time to wait for a race to occur after a thread has
  // acquired ownership of a watchpoint.
  kPauseTimeUs = 10 * 1000,  // 10ms
  kSampleTimeUs = 500 * 1000,  // 500ms

  // Maximum depth to use as a stack trace.
  kMaxStackTraceSize = 1,

  // The maximum number of memory accesses that can be recorded during a single
  // cycle of the monitor thread. This should be an even number.
  kMaxNumReports = 256,
  kMaxNumSamplePoints = kMaxNumReports / 2
};

static_assert(kCacheLineSize == (1 << kCacheLineShift),
              "Invalid shift amount to match cache line size.");

typedef uintptr_t TypeId;

struct StackTrace {
  uintptr_t pc[kMaxStackTraceSize];

  // Hash a stack trace to produce a (proxy for a) type ID.
  TypeId GetTypeId(void) const {
    auto h = pc[0];
    for (auto i = 1; i < kMaxStackTraceSize; ++i) {
      h = h * 31 + pc[i];
    }
    return h;
  }
};

struct MemoryAccessRecord {
  MemoryAccessRecord(void)
      : is_published(false) {}

  uintptr_t addr;
  uintptr_t size;
  StackTrace trace;
  pid_t thread_id;
  bool is_read;
  std::atomic<bool> is_published;
};

using MemoryAccessList = std::vector<const MemoryAccessRecord *>;

struct Allocation {
  uintptr_t addr;
  size_t size;
};

enum : uint8_t {
  kDisabled = 0,
  kEnabled = 1,
  kWritten = 2,
  kContended = 3
};

struct AllocationList {
  AllocationList(void)
      : next_alloc(0) {}

  void Add(uintptr_t addr, size_t size) {
    auto &alloc = allocations[next_alloc++ % kMaxNumSamplePoints];
    alloc.addr = addr;
    alloc.size = size;
  }

  unsigned next_alloc;
  Allocation allocations[kMaxNumSamplePoints];
};

typedef Allocation SamplePointList[kMaxNumSamplePoints];

// Maps allocation site hash to a stack trace.
static std::vector<TypeId> gTypeIds;
static std::set<TypeId> gIgnoreSet;
static std::unordered_map<TypeId, StackTrace> gAllocationSites;
static std::unordered_map<TypeId, AllocationList> gRecentAllocations;
static std::mutex gAllocationLock;

// The current stuff being sampled.
static AllocationList gSamplePoints;
static StackTrace gAllocStackTrace;
static size_t gTypeIdIndex = 0;  // Index into `gTypeIds`.
static TypeId gTypeId = 0;

// Global pointer to the shadow memory containing the watchpoints.
static Watchpoint *gWatchpoints = nullptr;

// Address to ignore in this thread. We don't want to "punish" a thread by
// constantly pausing on the same memory location if we didn't get a hit on
// the first access.
static size_t gSampleEpoch = 0;
static __thread size_t tWriteSampleEpoch = 0;
static __thread size_t tReadSampleEpoch = 0;
static __thread pid_t tTid = 0;

// Constant number of reports.
static MemoryAccessRecord gReports[kMaxNumReports];
static std::atomic<unsigned> gNextReport = ATOMIC_VAR_INIT(0);

// File descriptors.
static int gLogFd = -1;
static int gDevZero = -1;

// GNU ABI-specific reference to the program's name.
extern "C" const char *__progname __attribute__((weak));
static char gCwd[1024] = {'\0'};

// Buffer for temporary things.
static char gBuf[8192] = {'\0'};

// Allocate the shadow memory. Map it to /dev/zero so it's file backed and
// so that MAP_NORESERVE keeps the resident size down to only the pages that
// we use.
static bool InitShadowMemory(void) {
  errno = 0;
  if (-1 == gDevZero) gDevZero = open("/dev/zero", O_RDONLY);
  if (errno) return false;

  auto flags = MAP_PRIVATE | MAP_NORESERVE | MAP_FILE;
  if (gWatchpoints) flags |= MAP_FIXED;

  gWatchpoints = reinterpret_cast<Watchpoint *>(mmap(
      /*const_cast<uint8_t *>(gWatchpoints)*/ nullptr, kShadowSize,
      PROT_READ | PROT_WRITE, flags, gDevZero, 0));
  return 0 == errno;
}

__attribute__((always_inline))
inline static StackTrace GetStackTrace(void) {
  return {{reinterpret_cast<uintptr_t>(__builtin_return_address(0))}};
}

static pid_t gettid(void) {
  return syscall(SYS_gettid);
}

// Returns the index into the watchpoints memory of a given address. We want to
// do some extra swizzling for the indexing to avoid contention on the
// watchpoints themselves due to locality.
//
// If we direct mapped, we'd get this, where WP1 and WP2 might be in the same
// cache line:
//
//    | WP1 | WP2 |
//       |      \
//    | DDDD | DDDD | DDDD | DDDD
//
// What we want is:
//
//    | WP1 | ... | WP2 |
//       |         /
//    | DDDD | DDDD | DDDD | DDDD
//
inline static uintptr_t WatchpointIndex(uintptr_t addr) {
  return (addr / kGranularity) & (kNumWatchpoints - 1);
  //const auto base = addr / kGranularity;
  //return (base ^ (base << kCacheLineShift)) & (kNumWatchpoints - 1);
}

// Activate watchpoints across an entire sample point.
static void ActivateWatchpoints(uintptr_t addr, uintptr_t size) {
  uint8_t disabled = kDisabled;
  auto end_addr = addr + size + kGranularity;
  for (addr -= kGranularity; addr < end_addr; addr += kGranularity) {
    auto &wp = gWatchpoints[WatchpointIndex(addr)];
    if (wp.compare_exchange_strong(disabled, kEnabled)) {
      debug_write(2, ".", 1);
    }
  }
}

// Activate watchpoints for all sample points.
static bool ActivateWatchpoints(void) {
  gTypeId = 0;
  gAllocationLock.lock();
  if (!gTypeIds.empty()) {
    gTypeId = gTypeIds[gTypeIdIndex++ % gTypeIds.size()];
    gSamplePoints = gRecentAllocations[gTypeId];
    gAllocStackTrace = gAllocationSites[gTypeId];
  }
  gAllocationLock.unlock();

  if (!gTypeId || gIgnoreSet.count(gTypeId)) {
    return false;
  }

  for (const auto &alloc : gSamplePoints.allocations) {
    if (alloc.addr && alloc.size) {
      ActivateWatchpoints(alloc.addr, alloc.size);
    }
  }

  return true;
}

// Returns true if we've found a data race.
static bool IsDataRace(const MemoryAccessRecord *a1,
                       const MemoryAccessRecord *a2) {
  if (a2->addr < a1->addr) return IsDataRace(a2, a1);

  return a1->addr && a2->addr &&  // Need both accesses.
         !(a1->is_read && a2->is_read) &&  // Read and Read.
         a1->addr <= a2->addr &&  // Overlapping access.
         (a1->addr + a1->size) > a2->addr;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
static ssize_t PrintTrace(const StackTrace &trace, ssize_t size) {
  Dl_info info;
  for (auto pc : trace.pc) {
    if (!pc) continue;

    // Try to get the name of and offset into the shared object file that
    // contains this address.
    if (dladdr(reinterpret_cast<const void *>(pc), &info)) {
      auto addr = pc;
      if (static_cast<uint32_t>(pc) != pc) {
        addr = pc - reinterpret_cast<uintptr_t>(info.dli_fbase);
      }

      if ('/' == info.dli_fname[0]) {
        size += sprintf(&(gBuf[size]), "\t\t%s:%p\n", info.dli_fname, addr);
      } else {
        auto exe = info.dli_fname;
        if ('.' == info.dli_fname[0] && '/' == info.dli_fname[1]) {
          exe += 2;
        }
        size += sprintf(&(gBuf[size]), "\t\t%s/%s:%p\n", gCwd, exe, addr);
      }

    // Assume it's in the main executable.
    } else if (__progname && static_cast<uint32_t>(pc) == pc) {
      size += sprintf(&(gBuf[size]), "\t\t%s:%p\n", __progname, pc);

    // Dunno.
    } else {
      size += sprintf(&(gBuf[size]), "\t\t%p\n", pc);
    }
  }
  return size;
}

static ssize_t PrintAccess(const MemoryAccessRecord *a1, ssize_t size) {
  size += sprintf(&(gBuf[size]), "\t%s by thread %d (%u bytes at 0x%lx):\n",
                  (a1->is_read ? "Read" : "Written"),
                  a1->thread_id, a1->size, a1->addr);
  size = PrintTrace(a1->trace, size);
  return size;
}

// Report contention.
static void ReportDataRace(const MemoryAccessRecord *a1,
                           const MemoryAccessRecord *a2) {
  ssize_t size = 0;
  size += sprintf(&(gBuf[size]), "Data race detected:\n\tAllocated by:\n");
  size = PrintTrace(gAllocStackTrace, size);
  size = PrintAccess(a1, size);
  size = PrintAccess(a2, size);
  size += sprintf(&(gBuf[size]), "\n");

  write(gLogFd, gBuf, static_cast<size_t>(size));
}
#pragma clang diagnostic pop

// Report a data race among the recorded accesses to some memory.
static bool ReportDataRace(const MemoryAccessList &accesses) {
  auto found = false;
  for (auto i = 0; i < accesses.size(); ++i) {
    auto a1 = accesses[i];
    for (auto j = i + 1; j < accesses.size(); ++j) {
      auto a2 = accesses[j];
      if (IsDataRace(a1, a2)) {
        ReportDataRace(a1, a2);
        found = true;
      }
    }
  }
  return found;
}

static bool ReportDataRaces(void) {
  std::unordered_map<uintptr_t, MemoryAccessList> accesses;
  for (auto &report : gReports) {
    if (report.is_published.load(std::memory_order_acquire)) {
      auto idx = report.addr / kGranularity;
      accesses[idx].push_back(&report);
      report.is_published.store(false, std::memory_order_release);
    }
  }

  auto found = false;
  for (const auto &reports : accesses) {
    if (2 <= reports.second.size()) {
      found = ReportDataRace(reports.second) || found;
    }
  }

  return found;
}

// Enable/disable watchpoints over time.
static void MonitorThread(void) {
  if (!InitShadowMemory()) {
    return;
  }

  for (auto epoch = 1; ++epoch; ) {
    debug_write(2, "-", 1);
    if (!ActivateWatchpoints()) {
      debug_write(2, "_", 1);
      usleep(kSampleTimeUs * 10);
      continue;
    }

    gSampleEpoch = epoch;  // Enable checking.
    usleep(kSampleTimeUs);
    gSampleEpoch = 0;  // Disable checking.

    usleep(kSampleTimeUs);

    if (ReportDataRaces()) {
      debug_write(2, "!", 1);
      gIgnoreSet.insert(gTypeId);
    }

    usleep(kPauseTimeUs);
  }
}

// Initialize the contention sanitizer.
class RaceSanitizer {
 public:
  RaceSanitizer(void) {
    auto log_file = getenv("RSAN_LOG_FILE");

    if (!getcwd(gCwd, sizeof gCwd)) gCwd[0] = '\0';

    errno = 0;
    sprintf(gBuf, "%s.%d", log_file ? log_file : "/tmp/rsan", getpid());
    gLogFd = open(gBuf, O_WRONLY | O_APPEND | O_CREAT, 0666);
    if (errno) return;

    std::thread monitor(MonitorThread);
    monitor.detach();
  }
};

// Record that a thread accessed some memory.
static void RecordMemoryAccess(uintptr_t addr, size_t size,
                               bool is_read) noexcept {
  if (!tTid) tTid = gettid();
  auto &report = gReports[gNextReport.fetch_add(1) % kMaxNumReports];
  report.is_published.store(false, std::memory_order_acquire);
  report.addr = addr;
  report.size = size;
  report.trace = GetStackTrace();
  report.thread_id = tTid;
  report.is_read = is_read;
  report.is_published.store(true, std::memory_order_release);
}

// Is checking enabled?
inline static bool IsWriteCheckingEnabled(void) noexcept {
  return tWriteSampleEpoch < gSampleEpoch;
}

// Disable checking until the next sampling period.
inline static void DisableWriteChecking(void) noexcept {
  tWriteSampleEpoch = gSampleEpoch;
}

// Is checking enabled?
inline static bool IsReadCheckingEnabled(void) noexcept {
  return tReadSampleEpoch < gSampleEpoch;
}

// Disable checking until the next sampling period.
inline static void DisableReadChecking(void) noexcept {
  tReadSampleEpoch = gSampleEpoch;
}

template <size_t kScanSize, void (*kScanFunc)(uintptr_t)>
uintptr_t ScanApply(uintptr_t addr, size_t addr_max) noexcept {
  for (; addr + kScanSize < addr_max; addr += kScanSize) {
    kScanFunc(addr);
  }
  return addr;
}

inline static void __rsan_read(uintptr_t addr, size_t size) {
  if (!IsReadCheckingEnabled()) return;

  auto &state = gWatchpoints[WatchpointIndex(addr)];
  auto curr_state = state.load(std::memory_order_acquire);

  if (kDisabled == curr_state) {
    return;
  } else if (kWritten == curr_state) {
    if (state.compare_exchange_strong(curr_state, kContended)) {
      curr_state = kContended;
    }
  } else {
    debug_write(2, "r", 1);
  }

  if (kContended == curr_state) {
    debug_write(2, "R", 1);
    RecordMemoryAccess(addr, size, true);
    DisableReadChecking();
  }
}

inline static void __rsan_write(uintptr_t addr, size_t size) {
  if (!IsWriteCheckingEnabled()) return;

  auto &state = gWatchpoints[WatchpointIndex(addr)];
  auto curr_state = state.load(std::memory_order_acquire);
  auto owner = false;

  if (kDisabled == curr_state) {
    return;
  } else if (kEnabled == curr_state) {
    debug_write(2, "w", 1);
    if (state.compare_exchange_strong(curr_state, kWritten)) {
      usleep(kPauseTimeUs);
      curr_state = state.load(std::memory_order_acquire);
      owner = true;
      goto check_report;
    }
  } else if (kWritten == curr_state) {
    state.store(kContended, std::memory_order_release);
    curr_state = kContended;
  }

check_report:

  if (kContended == curr_state) {
    debug_write(2, "W", 1);
    RecordMemoryAccess(addr, size, false);
    if (owner) {
      state.store(kDisabled, std::memory_order_release);
    }
  } else if (owner) {
    state.store(kEnabled, std::memory_order_release);
  }

  DisableWriteChecking();
}

}  // namespace __rsan

extern "C" {

__attribute__((init_priority(65535), used))
RaceSanitizer __rsan_initializer;

// Interpose on dynamic memory allocation.
void __rsan_record_alloc(uintptr_t addr, size_t size) {
  if (!addr || !size) {
    return;
  }

  auto trace = GetStackTrace();
  auto type_id = trace.GetTypeId();

  if (!type_id) {
    return;
  }

  gAllocationLock.lock();
  auto &saved_trace = gAllocationSites[type_id];
  if (!saved_trace.pc[0]) {
    saved_trace = trace;
    gTypeIds.push_back(type_id);
    debug_write(2, "T", 1);
  }

  auto &allocs = gRecentAllocations[type_id];
  allocs.Add(addr, size);
  gAllocationLock.unlock();
}

// Replacement for `posix_memalign`, which needs some special handling.
int __rsan_posix_memalign(void **addr, size_t alignment, size_t size) {
  auto ret = posix_memalign(addr, alignment, size);
  if (!ret) __rsan_record_alloc(reinterpret_cast<uintptr_t>(*addr), size);
  return ret;
}

#define MAKE_RSAN_FUNC(name, is_write, size) \
  __attribute__((used, always_inline)) \
  inline void __rsan_ ## name ## _ ## size (uintptr_t addr) noexcept { \
    __rsan_ ## name (addr, size); \
  }

#define MAKE_RSAN_FUNC_FORWARD(name, is_write, size, actual_size) \
  __attribute__((used, always_inline)) \
  inline void __rsan_ ## name ## _ ## size (uintptr_t addr) noexcept { \
    __rsan_ ## name (addr, actual_size); \
  }

#define MAKE_RSAN_FUNC_CLASS(name, is_write) \
  MAKE_RSAN_FUNC(name,is_write,1) \
  MAKE_RSAN_FUNC(name,is_write,2) \
  MAKE_RSAN_FUNC(name,is_write,4) \
  MAKE_RSAN_FUNC(name,is_write,8) \
  MAKE_RSAN_FUNC(name,is_write,16) \
  MAKE_RSAN_FUNC(name,is_write,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,3,4) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,5,8) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,6,8) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,7,8) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,9,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,10,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,11,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,12,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,13,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,14,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,15,16) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,17,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,18,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,19,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,20,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,21,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,22,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,23,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,24,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,25,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,26,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,27,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,28,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,29,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,30,32) \
  MAKE_RSAN_FUNC_FORWARD(name,is_write,31,32)

MAKE_RSAN_FUNC_CLASS(read, false)
MAKE_RSAN_FUNC_CLASS(write, true)

#undef MAKE_RSAN_FUNC
#undef MAKE_RSAN_FUNC_CLASS

// Used to watch various LLVM intrinsics.
void __rsan_read_n(uintptr_t addr, size_t size) noexcept {
  const auto addr_max = addr + size;
  addr = ScanApply<16, __rsan_read_16>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<8, __rsan_read_8>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<4, __rsan_read_4>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<2, __rsan_read_2>(addr, addr_max);
  if (addr == addr_max) return;
  ScanApply<1, __rsan_read_1>(addr, addr_max);
}

void __rsan_write_n(uintptr_t addr, size_t size) noexcept {
  const auto addr_max = addr + size;
  addr = ScanApply<16, __rsan_write_16>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<8, __rsan_write_8>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<4, __rsan_write_4>(addr, addr_max);
  if (addr == addr_max) return;
  addr = ScanApply<2, __rsan_write_2>(addr, addr_max);
  if (addr == addr_max) return;
  ScanApply<1, __rsan_write_1>(addr, addr_max);
}

}  // extern C
