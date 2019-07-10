#ifndef DLALLOC_HEAP_H
#define DLALLOC_HEAP_H

#include "malloc.h"
#include "init.h"

/* Isolate the least set bit of a bitmap. */
#define least_bit(x)         ((x) & -(x))

/* Mask with all bits to left of least bit of x on. */
#define left_bits(x)         ((x << 1) | -(x << 1))

/* index corresponding to given bit. */
#define compute_bit2idx(X, I)\
{\
    unsigned int J;\
    J = __builtin_ctz(X); \
    I = (bin_index_t) J;\
}

static inline void *internal_malloc(dl_heap_t heap, size_t size) {
    if (heap == &global_malloc_state) {
        return dl_malloc(size);
    }
    else {
        return dl_heap_malloc(heap, size);
    }
}

static inline void internal_free(dl_heap_t heap, void *mem) {
    if (heap == &global_malloc_state) {
        dl_free(mem);
    }
    else {
        dl_heap_free(heap, mem);
    }
}

void *dl_malloc_impl(struct malloc_state *state, size_t nb);

void dl_free_impl(struct malloc_state *state, struct malloc_chunk *p);

void *tmalloc_small(struct malloc_state *state, size_t nb);

void *tmalloc_large(struct malloc_state *state, size_t nb);

void *internal_memalign(struct malloc_state *state, size_t alignment, size_t bytes);

size_t internal_bulk_free(struct malloc_state *state, void *array[], size_t nelem);

struct malloc_chunk *try_realloc_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t nb, int can_move);

void **ialloc(struct malloc_state *state, size_t n_elements, size_t *sizes, int opts, void *chunks[]);

#endif //DLALLOC_HEAP_H
