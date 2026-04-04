#include "slsan_rtl.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "slsan_interceptors.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

DECLARE_REAL_AND_INTERCEPTOR(void *, memcpy, void *to, const void *from,
                             uptr size);
DECLARE_REAL_AND_INTERCEPTOR(void *, memmove, void *to, const void *from,
                             uptr size);
DECLARE_REAL_AND_INTERCEPTOR(void *, memset, void *block, int c, uptr size);

#define UUID_STRING_LENGTH 37
#define INITIAL_SHARED_MEMORY_CAPACITY 16

namespace __sanitizer {
// VSNPrintf is defined in sanitizer_printf.cpp and uses a custom printf
// implementation that doesn't call any intercepted libc functions.
int VSNPrintf(char *buff, int buff_length, const char *format, va_list args);
} // namespace __sanitizer

namespace __slsan {

struct ShmInfo {
  void *addr;
  size_t length;
  char uuid[UUID_STRING_LENGTH];
};

struct ShmMap {
  ShmInfo *entries;
  size_t count;
  size_t capacity;
};

// -------------------------- Globals --------------------- {{{1
static StaticSpinMutex slsan_inited_mutex;
static atomic_uint8_t slsan_inited = {0};
static ShmMap slsan_shm_map = {NULL, 0, 0};
static Mutex slsan_shm_map_mutex;

// -------------------------- Run-time entry ------------------- {{{1
static void SetSlsanInited() {
  atomic_store(&slsan_inited, 1, memory_order_release);
}

bool SlsanInited() {
  return atomic_load(&slsan_inited, memory_order_acquire) == 1;
}

static void InitializeFlags() {
  SetCommonFlagsDefaults();

  FlagParser parser;
  RegisterCommonFlags(&parser);

  InitializeCommonFlags();
  if (Verbosity())
    ReportUnrecognizedFlags();

  if (common_flags()->help)
    parser.PrintFlagDescriptions();
}

static bool SlsanInitInternal() {
  if (LIKELY(SlsanInited()))
    return true;
  InitializeFlags();
  InitializeInterceptors();
  SetSlsanInited();
  return true;
}

void SlsanInitFromRtl() {
  if (LIKELY(SlsanInited()))
    return;
  SpinMutexLock lock(&slsan_inited_mutex);
  SlsanInitInternal();
}

bool TrySlsanInitFromRtl() {
  if (LIKELY(SlsanInited()))
    return true;
  if (!slsan_inited_mutex.TryLock())
    return false;
  bool result = SlsanInitInternal();
  slsan_inited_mutex.Unlock();
  return result;
}

static void ensure_shm_capacity() {
  if (slsan_shm_map.count >= slsan_shm_map.capacity) {
    size_t new_capacity = slsan_shm_map.capacity
                              ? slsan_shm_map.capacity * 2
                              : INITIAL_SHARED_MEMORY_CAPACITY;
    ShmInfo *new_entries =
        (ShmInfo *)InternalAlloc(new_capacity * sizeof(ShmInfo));
    if (slsan_shm_map.entries) {
      internal_memcpy(new_entries, slsan_shm_map.entries,
                      slsan_shm_map.count * sizeof(ShmInfo));
      InternalFree(slsan_shm_map.entries);
    }
    slsan_shm_map.entries = new_entries;
    slsan_shm_map.capacity = new_capacity;
  }
}

// Returns true if addr overlaps a tracked shm region, copying its uuid into
// out_uuid. Caller must hold at least a read lock on slsan_shm_map_mutex.
static bool get_shm_uuid(const void *addr, size_t size,
                          char out_uuid[UUID_STRING_LENGTH]) {
  for (size_t i = 0; i < slsan_shm_map.count; i++) {
    uptr base = (uptr)slsan_shm_map.entries[i].addr;
    size_t len = slsan_shm_map.entries[i].length;
    uptr end = base + len;
    uptr access_end = (uptr)addr + size;

    // check if there is any overlap
    if ((uptr)addr < end && access_end > base) {
      internal_memcpy(out_uuid, slsan_shm_map.entries[i].uuid,
                      UUID_STRING_LENGTH);
      return true;
    }
  }
  return false;
}

static void slsan_log(const char *fmt, ...) {
  char buf[8192];
  // Reserve space for "[SLSAN] " prefix (8 bytes)
  static const char kPrefix[] = "[SLSAN] ";
  static const uptr kPrefixLen = sizeof(kPrefix) - 1;
  internal_memcpy(buf, kPrefix, kPrefixLen);
  va_list ap;
  va_start(ap, fmt);
  // Use VSNPrintf from sanitizer_common - it's a custom implementation
  // that doesn't call any intercepted libc functions.
  int len = VSNPrintf(buf + kPrefixLen, sizeof(buf) - kPrefixLen, fmt, ap);
  va_end(ap);
  if (len > 0) {
    // internal_write is a direct syscall — atomic for writes <= PIPE_BUF,
    // no stdio buffering, not intercepted.
    internal_write(1, buf, kPrefixLen + (uptr)len);
  }
}

static void get_backtrace(char *buffer, size_t buf_sz) {
  if (buffer == NULL || buf_sz == 0) {
    return;
  }
  void *array[32];
  int n = backtrace(array, 32);

  size_t offset = 0;
  Dl_info info;
  for (int i = 0; i < n && offset < buf_sz; i++) {
    if (dladdr(array[i], &info)) {
      uintptr_t ip_offset = (uptr)array[i] - (uptr)info.dli_fbase;
      offset += internal_snprintf(buffer + offset, buf_sz - offset, " \"%s\"+0x%lx",
                         info.dli_fname, (uptr)ip_offset);
    } else {
      offset += internal_snprintf(buffer + offset, buf_sz - offset, " %p", array[i]);
    }
  }
}

} // namespace __slsan

// ---------------------- Interface ---------------- {{{1
using namespace __slsan;

void __slsan_post_mmap(void *addr, SIZE_T length, int prot, int flags, int fd,
                       OFF64_T offset) {
  if (addr == MAP_FAILED)
    return;
  if (flags & MAP_SHARED) {
    char uuid_str[UUID_STRING_LENGTH];
    {
      u8 b[16];
      GetRandom(b, sizeof(b));
      // Set UUID version 4 and variant bits
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      internal_snprintf(uuid_str, UUID_STRING_LENGTH,
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                        "%02x%02x%02x%02x%02x%02x",
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }

    {
      Lock l(&slsan_shm_map_mutex);
      ensure_shm_capacity();
      ShmInfo *info = &slsan_shm_map.entries[slsan_shm_map.count++];
      info->addr = addr;
      info->length = length;
      internal_memcpy(info->uuid, uuid_str, UUID_STRING_LENGTH);
    }

    // Capture backtrace at the point of mmap() call
    char bt[4096];
    bt[0] = '\0';
    get_backtrace(bt, sizeof(bt));

    // Structured log format for detect_risks.py parsing:
    // [SLSAN] type=mmap pid=%d tid=%d addr=%p size=%zu uuid=%s bt=%s
    slsan_log("type=mmap pid=%d tid=%d addr=%p size=%zu uuid=%s bt=%s\n",
              getpid(), gettid(), addr, (size_t)length, uuid_str, bt);
  }
}

void __slsan_pre_munmap(void *addr, SIZE_T length) {
  bool found = false;
  {
    Lock l(&slsan_shm_map_mutex);
    for (size_t i = 0; i < slsan_shm_map.count; i++) {
      if (slsan_shm_map.entries[i].addr == addr) {
        if (i < slsan_shm_map.count - 1) {
          slsan_shm_map.entries[i] =
              slsan_shm_map.entries[slsan_shm_map.count - 1];
        }
        slsan_shm_map.count--;
        found = true;
        break;
      }
    }
  }
  if (found)
    slsan_log("type=munmap pid=%d tid=%d addr=%p size=%zu\n",
              getpid(), gettid(), addr, (size_t)length);
}

void __slsan_mem_access(const void *addr, uptr size, int is_write) {
  char uuid[UUID_STRING_LENGTH];
  {
    ReadLock l(&slsan_shm_map_mutex);
    if (!get_shm_uuid(addr, size, uuid))
      return;
  }

  // Read value from memory at access time
  uint64_t val = 0;
  internal_memcpy(&val, addr, size < 8 ? size : 8);

  char bt[4096];
  bt[0] = '\0';
  get_backtrace(bt, sizeof(bt));

  // Structured log format for detect_risks.py parsing:
  // [SLSAN] type=%s pid=%d tid=%d addr=%p val=%lu size=%zu uuid=%s bt=%s
  const char *type = is_write ? "store" : "load";
  slsan_log("type=%s pid=%d tid=%d addr=%p val=%lu size=%zu uuid=%s bt=%s\n",
             type, getpid(), gettid(), addr, (unsigned long)val, (size_t)size, uuid, bt);
}

void *__slsan_memcpy(void *to, const void *from, uptr size) {
  return WRAP(memcpy)(to, from, size);
}

void *__slsan_memset(void *block, int c, uptr size) {
  return WRAP(memset)(block, c, size);
}

void *__slsan_memmove(void *to, const void *from, uptr size) {
  return WRAP(memmove)(to, from, size);
}

__attribute__((constructor(0))) void __slsan_init() { SlsanInitFromRtl(); }
