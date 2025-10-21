
#define SANITIZER_COMMON_NO_REDEFINE_BUILTINS

#include "slsan_interceptors.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "slsan_rtl.h"

using namespace __slsan;

#undef SANITIZER_INTERCEPT_REALPATH
#define SANITIZER_INTERCEPT_REALPATH 0

#undef SANITIZER_INTERCEPT_WRITE
#define SANITIZER_INTERCEPT_WRITE 0

#undef SANITIZER_INTERCEPT_READ
#define SANITIZER_INTERCEPT_READ 0

DECLARE_REAL(SIZE_T, strnlen, const char *s, SIZE_T maxlen)
DECLARE_REAL(void *, memcpy, void *to, const void *from, uptr size)
DECLARE_REAL(void *, memset, void *block, int c, uptr size)

namespace __slsan {
#define SLSAN_READ_STRING_OF_LEN(ctx, s, len, n)                               \
  COMMON_INTERCEPTOR_READ_RANGE(                                               \
      (ctx), (s), common_flags()->strict_string_checks ? (len) + 1 : (n))

#define SLSAN_INTERCEPTOR_ENTER(ctx, func, ...)                                \
  ctx = (void *)0;                                                             \
  (void)ctx;                                                                   \
  do {                                                                         \
    if (!TrySlsanInitFromRtl())                                                \
      return internal_##func(__VA_ARGS__);                                     \
  } while (false)

static inline uptr MaybeRealStrnlen(const char *s, uptr maxlen) {
#if SANITIZER_INTERCEPT_STRNLEN
  if (REAL(strnlen)) {
    return REAL(strnlen)(s, maxlen);
  }
#endif
  return internal_strnlen(s, maxlen);
}
} // namespace __slsan

// ---------------------- Wrappers ---------------- {{{1

#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                               \
  ctx = (void *)0;                                                             \
  (void)ctx;                                                                   \
  do {                                                                         \
    if (!TrySlsanInitFromRtl())                                                \
      return REAL(func)(__VA_ARGS__);                                          \
  } while (false)

#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size)                          \
  __slsan_mem_load(ptr, size)

#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size)                         \
  __slsan_mem_store(ptr, size)

#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path)                              \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name)                          \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_ON_EXIT(ctx) (0)

#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name)                 \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!SlsanInited())

#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)

#define COMMON_INTERCEPT_FUNCTION_VER_UNVERSIONED_FALLBACK(name, ver)          \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION_VER(name, ver) && !INTERCEPT_FUNCTION(name))       \
      VReport(1, "SGXLogicSanitizer: failed to intercept '%s@@%s' or '%s'\n",  \
              #name, ver, #name);                                              \
  } while (0)

#define COMMON_INTERCEPT_FUNCTION(name)                                        \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION(name))                                             \
      VReport(1, "SGXLogicSanitizer: failed to intercept '%s'\n", #name);      \
  } while (0)

#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd)                    \
  do {                                                                         \
  } while (false)

template <class Mmap>
static void *mmap_interceptor(Mmap real_mmap, void *addr, SIZE_T length,
                              int prot, int flags, int fd, OFF64_T offset) {
  void *res = real_mmap(addr, length, prot, flags, fd, offset);
  __slsan_post_mmap(res, length, prot, flags, fd, offset);
  return res;
}

template <class Munmap>
static int munmap_interceptor(Munmap real_munmap, void *addr, SIZE_T length) {
  __slsan_pre_munmap(addr, length);
  return real_munmap(addr, length);
}

#define COMMON_INTERCEPTOR_MMAP_IMPL(ctx, mmap, addr, length, prot, flags, fd, \
                                     offset)                                   \
  do {                                                                         \
    (void)(ctx);                                                               \
    return mmap_interceptor(REAL(mmap), addr, sz, prot, flags, fd, off);       \
  } while (false)

#define COMMON_INTERCEPTOR_MUNMAP_IMPL(ctx, addr, length)                      \
  do {                                                                         \
    (void)(ctx);                                                               \
    return munmap_interceptor(REAL(munmap), addr, sz);                         \
  } while (false)

#define COMMON_INTERCEPTOR_STRNDUP_IMPL(ctx, s, size)                          \
  COMMON_INTERCEPTOR_ENTER(ctx, strndup, s, size);                             \
  uptr copy_length = internal_strnlen(s, size);                                \
  if (common_flags()->intercept_strndup) {                                     \
    COMMON_INTERCEPTOR_READ_STRING(ctx, s, Min(size, copy_length + 1));        \
  }                                                                            \
  return REAL(strndup)(s, size);

#include "sanitizer_common/sanitizer_common_interceptors.inc"
#include "sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc"

// For both strcat() and strncat() we need to check the validity of |to|
// argument irrespective of the |from| length.
INTERCEPTOR(char *, strcat, char *to, const char *from) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, strcat, to, from);
  uptr from_length = internal_strlen(from);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, from, from_length + 1);
  uptr to_length = internal_strlen(to);
  SLSAN_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
  COMMON_INTERCEPTOR_WRITE_RANGE(ctx, to + to_length, from_length + 1);
  return REAL(strcat)(to, from);
}

INTERCEPTOR(char *, strncat, char *to, const char *from, uptr size) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, strncat, to, from, size);
  uptr from_length = MaybeRealStrnlen(from, size);
  uptr copy_length = Min(size, from_length + 1);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, from, copy_length);
  uptr to_length = internal_strlen(to);
  SLSAN_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
  COMMON_INTERCEPTOR_WRITE_RANGE(ctx, to + to_length, from_length + 1);
  return REAL(strncat)(to, from, size);
}

INTERCEPTOR(char *, strcpy, char *to, const char *from) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, strcpy, to, from);
  uptr from_size = internal_strlen(from) + 1;
  COMMON_INTERCEPTOR_READ_RANGE(ctx, from, from_size);
  COMMON_INTERCEPTOR_WRITE_RANGE(ctx, to, from_size);
  return REAL(strcpy)(to, from);
}

INTERCEPTOR(char *, strdup, const char *s) {
  void *ctx;
  SLSAN_INTERCEPTOR_ENTER(ctx, strdup, s);
  uptr length = internal_strlen(s);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, s, length + 1);
  return REAL(strdup)(s);
}

INTERCEPTOR(char *, __strdup, const char *s) {
  void *ctx;
  SLSAN_INTERCEPTOR_ENTER(ctx, strdup, s);
  uptr length = internal_strlen(s);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, s, length + 1);
  return REAL(strdup)(s);
}

INTERCEPTOR(char *, strncpy, char *to, const char *from, uptr size) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, strncpy, to, from, size);
  uptr from_size = Min(size, MaybeRealStrnlen(from, size) + 1);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, from, from_size);
  COMMON_INTERCEPTOR_WRITE_RANGE(ctx, to, size);
  return REAL(strncpy)(to, from, size);
}

template <typename Fn>
static ALWAYS_INLINE auto StrtolImpl(void *ctx, Fn real, const char *nptr,
                                     char **endptr, int base)
    -> decltype(real(nullptr, nullptr, 0)) {
  char *real_endptr;
  auto res = real(nptr, &real_endptr, base);
  StrtolFixAndCheck(ctx, nptr, endptr, real_endptr, base);
  return res;
}

#define INTERCEPTOR_STRTO_BASE(ret_type, func)                                 \
  INTERCEPTOR(ret_type, func, const char *nptr, char **endptr, int base) {     \
    void *ctx;                                                                 \
    COMMON_INTERCEPTOR_ENTER(ctx, func, nptr, endptr, base);                   \
    return StrtolImpl(ctx, REAL(func), nptr, endptr, base);                    \
  }

INTERCEPTOR_STRTO_BASE(long, strtol)
INTERCEPTOR_STRTO_BASE(long long, strtoll)

#if SANITIZER_GLIBC
INTERCEPTOR_STRTO_BASE(long, __isoc23_strtol)
INTERCEPTOR_STRTO_BASE(long long, __isoc23_strtoll)
#endif

INTERCEPTOR(int, atoi, const char *nptr) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, atoi, nptr);
  char *real_endptr;
  // "man atoi" tells that behavior of atoi(nptr) is the same as
  // strtol(nptr, 0, 10), i.e. it sets errno to ERANGE if the
  // parsed integer can't be stored in *long* type (even if it's
  // different from int). So, we just imitate this behavior.
  int result = REAL(strtol)(nptr, &real_endptr, 10);
  FixRealStrtolEndptr(nptr, &real_endptr);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

INTERCEPTOR(long, atol, const char *nptr) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, atol, nptr);
  char *real_endptr;
  long result = REAL(strtol)(nptr, &real_endptr, 10);
  FixRealStrtolEndptr(nptr, &real_endptr);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

INTERCEPTOR(long long, atoll, const char *nptr) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, atoll, nptr);
  char *real_endptr;
  long long result = REAL(strtoll)(nptr, &real_endptr, 10);
  FixRealStrtolEndptr(nptr, &real_endptr);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

// ---------------------- InitializeSlsanInterceptors ---------------- {{{1
namespace __slsan {
void InitializeInterceptors() {
  static bool initialized = false;
  if (initialized) {
    return;
  }
  initialized = true;

  InitializeCommonInterceptors();

  // Intercept str* functions.
  INTERCEPT_FUNCTION(strcat);
  INTERCEPT_FUNCTION(strcpy);
  INTERCEPT_FUNCTION(strncat);
  INTERCEPT_FUNCTION(strncpy);
  INTERCEPT_FUNCTION(strdup);
  INTERCEPT_FUNCTION(__strdup);

  INTERCEPT_FUNCTION(atoi);
  INTERCEPT_FUNCTION(atol);
  INTERCEPT_FUNCTION(atoll);
  INTERCEPT_FUNCTION(strtol);
  INTERCEPT_FUNCTION(strtoll);
#if SANITIZER_GLIBC
  INTERCEPT_FUNCTION(__isoc23_strtol);
  INTERCEPT_FUNCTION(__isoc23_strtoll);
#endif
}

} // namespace __slsan