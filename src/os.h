#ifndef MALLOC_ALLOC_H
#define MALLOC_ALLOC_H

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define __USE_GNU 1

#include <sys/mman.h>

#undef __USE_GNU

#include "config.h"
#include "sbrk.h"

/* MORECORE and MMAP must return MFAIL on failure */
#define MFAIL                   ((void*) -1)

static inline void *call_sbrk(intptr_t increment) {
#if defined(DISABLE_SBRK)
    (void) increment; // unused
    return MFAIL;
#elif defined(EMULATE_SBRK)
    return emulate_sbrk(increment);
#elif !defined(__APPLE__)
    return sbrk(increment);
#else
    (void) increment; // unused
    return MFAIL;
#endif
}

static inline void *call_mmap(size_t size) {
    return mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static inline int call_munmap(void *p, size_t size) {
    return munmap(p, size);
}

static inline void *call_mremap(void *old_address, size_t old_size, size_t new_size, int flags) {
#if !defined(__APPLE__)
    return mremap(old_address, old_size, new_size, flags);
#else
    (void) old_address; // unused
    (void) old_size; // unused
    (void) new_size; // unused
    (void) flags; // unused
    return MFAIL;
#endif
}

struct malloc_state;
struct malloc_chunk;

void *mmap_alloc(struct malloc_state *state, size_t size);

struct malloc_chunk *mmap_resize(struct malloc_state *state, struct malloc_chunk *old_p, size_t size, int flags);

void *sys_alloc(struct malloc_state *state, size_t size);

int sys_trim(struct malloc_state *state, size_t pad);

size_t release_unused_segments(struct malloc_state *state);

#endif //MALLOC_ALLOC_H
