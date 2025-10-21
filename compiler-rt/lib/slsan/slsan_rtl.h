#ifndef SLSAN_RTL_H
#define SLSAN_RTL_H

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using __sanitizer::uptr;

namespace __slsan {
bool SlsanInited();
void SlsanInitFromRtl();
bool TrySlsanInitFromRtl();
} // namespace __slsan

#if defined(__cplusplus)
extern "C" {
#endif

SANITIZER_INTERFACE_ATTRIBUTE void __slsan_post_mmap(void *addr, SIZE_T length,
                                                     int prot, int flags,
                                                     int fd, OFF_T offset);
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_pre_munmap(void *addr,
                                                      SIZE_T length);
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_mem_load(const void *addr,
                                                    uptr size);
SANITIZER_INTERFACE_ATTRIBUTE void __slsan_mem_store(const void *addr,
                                                     uptr size);
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

#endif