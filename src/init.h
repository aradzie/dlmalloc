#ifndef MALLOC_INIT_H
#define MALLOC_INIT_H

#include "state.h"

/*
  malloc_params holds global properties, including those that can be
  dynamically set using mallopt. There is a single instance, params,
  initialized in init_params. Note that the non-zeroness of "magic"
  also serves as an initialization flag.
*/

struct malloc_params {
    size_t magic;
    size_t page_size;
    size_t granularity;
    size_t mmap_threshold;
    size_t trim_threshold;
    flag_t default_flags;
};

extern struct malloc_params params;

int init_params(void);

int change_param(int param_number, int value);

/* Ensure params initialized */
static inline void ensure_initialization() {
    if (params.magic == 0) {
        init_params();
    }
}

/* The global malloc_state used for all non-"dl_heap_t" calls */
extern struct malloc_state global_malloc_state;

static inline int is_global(struct malloc_state *state) {
    return state == &global_malloc_state;
}

/* page-align a size */
static inline size_t page_align(size_t size) {
    return (size + (params.page_size - (size_t) 1)) & ~(params.page_size - (size_t) 1);
}

static inline int is_page_aligned(void *size) {
    return ((size_t) size & (params.page_size - (size_t) 1)) == 0;
}

/* granularity-align a size */
static inline size_t granularity_align(size_t size) {
    return (size + (params.granularity - (size_t) 1)) & ~(params.granularity - (size_t) 1);
}

/* For mmap, use granularity alignment on windows, else page-align */
static inline size_t mmap_align(size_t size) {
    return page_align(size);
}

#endif //MALLOC_INIT_H
