// GLOBAL WEAK stubs for SLSAN interface functions.
//
// DSOs built with -fsanitize=sgx-logic link this file so that
// --no-undefined is satisfied at link time.  At runtime the dynamic
// linker resolves these weak symbols to the strong definitions in the
// main binary (which links the full clang_rt.slsan.a).
//
// All stubs must have default visibility so they appear in .dynsym and
// can be overridden by the main binary's strong definitions.

#include "sanitizer_common/sanitizer_internal_defs.h"
#include <stdio.h>
#include <stdlib.h>

using __sanitizer::uptr;

extern "C" {

SANITIZER_WEAK_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE void
__slsan_mem_access(const void *addr, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_mem_access\n");
  abort();
}

SANITIZER_WEAK_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE void *
__slsan_memcpy(void *to, const void *from, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memcpy\n");
  abort();
}

SANITIZER_WEAK_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE void *
__slsan_memset(void *block, int c, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memset\n");
  abort();
}

SANITIZER_WEAK_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE void *
__slsan_memmove(void *to, const void *from, uptr size) {
  fprintf(stderr, "Shouldn't call this weak version of __slsan_memmove\n");
  abort();
}
}