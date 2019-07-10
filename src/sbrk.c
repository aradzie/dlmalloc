#include <errno.h>
#include <sys/types.h>

#include "sbrk.h"

#ifndef SBRK_SIZE
#define SBRK_SIZE (4 * 1024 * 1024)
#endif /* SBRK_SIZE */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((aligned(4096)))
#if defined(__linux__)
__attribute__((section("SBRK")))
#elif defined(__APPLE__)
__attribute__((section("__DATA,SBRK")))
#endif
#endif
static char sbrk_data[SBRK_SIZE];

static char *sbrk_curr = sbrk_data;

void *emulate_sbrk(ssize_t increment) {
    ssize_t sbrk_alloc = sbrk_curr - sbrk_data;
    ssize_t sbrk_new_alloc = sbrk_alloc + increment;
    if (sbrk_new_alloc < 0 || sbrk_new_alloc > SBRK_SIZE) {
        errno = ENOMEM;
        return (void *) -1;
    }
    void *p = sbrk_curr;
    sbrk_curr += increment;
    return p;
}
