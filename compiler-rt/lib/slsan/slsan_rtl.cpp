#include "slsan_rtl.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "slsan_interceptors.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define USE_FLOCK 0

DECLARE_REAL_AND_INTERCEPTOR(void *, memcpy, void *to, const void *from,
                             uptr size);
DECLARE_REAL_AND_INTERCEPTOR(void *, memmove, void *to, const void *from,
                             uptr size);
DECLARE_REAL_AND_INTERCEPTOR(void *, memset, void *block, int c, uptr size);

#define UUID_STRING_LENGTH 37
#define INITIAL_SHARED_MEMORY_CAPACITY 16

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
static pthread_mutex_t slsan_log_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// Initialize as requested from some part of SLSan runtime library
// (interceptors, allocator, etc).
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
    ShmInfo *new_entries = (ShmInfo *)malloc(new_capacity * sizeof(ShmInfo));
    if (slsan_shm_map.entries) {
      memcpy(new_entries, slsan_shm_map.entries,
             slsan_shm_map.count * sizeof(ShmInfo));
      free(slsan_shm_map.entries);
    }
    slsan_shm_map.entries = new_entries;
    slsan_shm_map.capacity = new_capacity;
  }
}

static const char *get_shm_uuid(const void *addr, size_t size) {
  for (size_t i = 0; i < slsan_shm_map.count; i++) {
    uptr base = (uptr)slsan_shm_map.entries[i].addr;
    size_t len = slsan_shm_map.entries[i].length;
    uptr end = base + len;
    uptr access_end = (uptr)addr + size;

    // check if there is any overlap
    if ((uptr)addr < end && access_end > base) {
      return slsan_shm_map.entries[i].uuid;
    }
  }
  return "";
}

static char *dup_slsan_log_prefix() {
  static thread_local bool slsan_log_prefix_initialized = false;
  static thread_local char slsan_log_prefix[PATH_MAX] = {0};
  if (!slsan_log_prefix_initialized) {
    if (const char *env = getenv("SLSAN_LOG_PREFIX")) {
      strncpy(slsan_log_prefix, env, PATH_MAX - 1);
      slsan_log_prefix[PATH_MAX - 1] = '\0';
    }
    slsan_log_prefix_initialized = true;
  }
  return strndup(slsan_log_prefix, PATH_MAX);
}

static void slsan_log(const char *fmt, ...) {
  // pthread_mutex_lock(&slsan_log_mutex);

  char *prefix = dup_slsan_log_prefix();
  char file_path[PATH_MAX];
  if (prefix != NULL && strlen(prefix) > 0 &&
      snprintf(file_path, sizeof(file_path), "%sslsan.log", prefix) > 0) {
    int fd = open(file_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd != -1) {
#if USE_FLOCK
      struct flock fl = {
          .l_type = F_WRLCK,
          .l_whence = SEEK_SET,
          .l_start = 0,
          .l_len = 0,
      };
      if (fcntl(fd, F_SETLKW, &fl) != -1) {
#endif
        char buf[BUFSIZ];
        buf[0] = '\0';
        va_list ap;
        va_start(ap, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (len > 0 && lseek(fd, 0, SEEK_END) != -1) {
          write(fd, buf, len);
        }

#if USE_FLOCK
        fl.l_type = F_UNLCK;
        if (fcntl(fd, F_SETLK, &fl) == -1) {
          perror("fcntl unlock in slsan_log()");
          abort();
        }
      }
#endif

      if (close(fd) != 0) {
        perror("close in slsan_log()");
        abort();
      }
    }
  }
  free(prefix);

  // pthread_mutex_unlock(&slsan_log_mutex);
}

static void get_backtrace(char *buffer, size_t buf_sz) {
  if (buffer == NULL || buf_sz == 0) {
    return;
  }
  void *array[100];
  int n = backtrace(array, 100);

  size_t offset = 0;
  Dl_info info;
  for (int i = 0; i < n && offset < buf_sz; i++) {
    if (dladdr(array[i], &info)) {
      uintptr_t ip_offset = (uptr)array[i] - (uptr)info.dli_fbase;
      offset += snprintf(buffer + offset, buf_sz - offset, " \"%s\"+0x%lx",
                         info.dli_fname, ip_offset);
    } else {
      offset += snprintf(buffer + offset, buf_sz - offset, " %p", array[i]);
    }
  }
}

} // namespace __slsan

// ---------------------- Interface ---------------- {{{1
using namespace __slsan;

void __slsan_post_mmap(void *addr, SIZE_T length, int prot, int flags, int fd,
                       OFF64_T offset) {
  if (flags & MAP_SHARED) {
    // generate uuid
    char uuid_str[UUID_STRING_LENGTH];
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse_lower(binuuid, uuid_str);

    // record to map
    ensure_shm_capacity();
    ShmInfo *info = &slsan_shm_map.entries[slsan_shm_map.count++];
    info->addr = addr;
    info->length = length;
    strncpy(info->uuid, uuid_str, UUID_STRING_LENGTH - 1);
    info->uuid[UUID_STRING_LENGTH - 1] = '\0';

    slsan_log(
        "== WARNING == [PID:%d TID:%d] mmap is called: addr=%p, length=%zu, "
        "prot=%d, flags=%d, fd=%d, offset=%ld, uuid=%s\n",
        getpid(), gettid(), addr, length, prot, flags, fd, (long)offset,
        uuid_str);
  }
}

void __slsan_pre_munmap(void *addr, SIZE_T length) {
  for (size_t i = 0; i < slsan_shm_map.count; i++) {
    if (slsan_shm_map.entries[i].addr == addr) {
      if (i < slsan_shm_map.count - 1) {
        slsan_shm_map.entries[i] =
            slsan_shm_map.entries[slsan_shm_map.count - 1];
      }
      slsan_shm_map.count--;
      slsan_log("== WARNING == [PID:%d TID:%d] munmap is called: addr=%p, "
                "length=%zu\n",
                getpid(), gettid(), addr, length);
      break;
    }
  }
}

void __slsan_mem_load(const void *addr, uptr size) {
  const char *uuid = get_shm_uuid(addr, size);
  if (uuid[0] == '\0') {
    return;
  }

  char bt[BUFSIZ];
  bt[0] = '\0';
  get_backtrace(bt, sizeof(bt));
  slsan_log("== WARNING == [PID:%d TID:%d] load memory: addr=%p, uuid=%s, "
            "size=%zu, backtrace:%s\n",
            getpid(), gettid(), addr, uuid, size, bt);
}

void __slsan_mem_store(const void *addr, size_t size) {
  const char *uuid = get_shm_uuid(addr, size);
  if (uuid[0] == '\0') {
    return;
  }

  char bt[BUFSIZ];
  bt[0] = '\0';
  get_backtrace(bt, sizeof(bt));
  slsan_log("== WARNING == [PID:%d TID:%d] store memory: addr=%p, uuid=%s, "
            "size=%zu, backtrace:%s\n",
            getpid(), gettid(), addr, uuid, size, bt);
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