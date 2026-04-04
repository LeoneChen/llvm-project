#ifndef SLSAN_RTL_H
#define SLSAN_RTL_H

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include <stdint.h>

using __sanitizer::uptr;

namespace __slsan {
bool SlsanInited();
void SlsanInitFromRtl();
bool TrySlsanInitFromRtl();
} // namespace __slsan

#if defined(__cplusplus)
extern "C" {
#endif

// mmap/munmap tracking
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_post_mmap(void *addr, SIZE_T length,
                                                     int prot, int flags,
                                                     int fd, OFF64_T offset);
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_pre_munmap(void *addr,
                                                      SIZE_T length);

// Memory access logging
// Called by IR instrumentation pass: logs address + size + access type
// Value is read by the runtime at the access address
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_mem_access(const void *addr,
                                                     uptr size,
                                                     int is_write);

// Bulk memory operations (unchanged)
SANITIZER_INTERFACE_ATTRIBUTE void *__slsan_memcpy(void *to, const void *from,
                                                   uptr size);
SANITIZER_INTERFACE_ATTRIBUTE void *__slsan_memmove(void *to, const void *from,
                                                    uptr size);
SANITIZER_INTERFACE_ATTRIBUTE void *__slsan_memset(void *block, int c,
                                                   uptr size);
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_init();

#if defined(__cplusplus)
}
#endif

#endif // SLSAN_RTL_H
