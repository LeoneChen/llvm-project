#include "sanitizer_common/sanitizer_internal_defs.h"
#include <stdio.h>
#include <stdlib.h>

using __sanitizer::uptr;

extern "C" {
SANITIZER_WEAK_ATTRIBUTE void __slsan_mem_load(const void *addr, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_mem_load\n");
  abort();
}
SANITIZER_WEAK_ATTRIBUTE void __slsan_mem_store(const void *addr, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_mem_store\n");
  abort();
}
SANITIZER_WEAK_ATTRIBUTE void *__slsan_memcpy(void *to, const void *from,
                                              uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memcpy\n");
  abort();
}
SANITIZER_WEAK_ATTRIBUTE void *__slsan_memset(void *block, int c, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memset\n");
  abort();
}
SANITIZER_WEAK_ATTRIBUTE void *__slsan_memmove(void *to, const void *from,
                                               uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memmove\n");
  abort();
}
}
