/* Real compiler input shared by the ELF, Mach-O and PE/PDB laboratory builds. */
#ifdef RUNTIME_PROOF
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#endif

static __attribute__((always_inline)) inline int inline_add(int value) {
    volatile int increment = 2;
    return value + increment;
}

__attribute__((noinline)) int native_leaf(int value) {
    volatile int result = inline_add(value);
    return result;
}

__attribute__((noinline)) int native_parent(int value) {
    return native_leaf(value) + 1;
}

int main(void) {
    int result = native_parent(39);
#ifdef RUNTIME_PROOF
    Dl_info image;
    if (!dladdr((void *)native_leaf, &image)) return 2;
    printf("{\"address\":\"0x%lx\",\"result\":%d}\n",
           (unsigned long)((uintptr_t)native_leaf - (uintptr_t)image.dli_fbase), result);
#endif
    return result == 42 ? 0 : 1;
}
