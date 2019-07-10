#include <errno.h>
#include <sys/types.h>
#include <string.h>

#include "assert.h"
#include "check.h"
#include "chunk.h"
#include "config.h"
#include "debug.h"
#include "error.h"
#include "heap.h"
#include "init.h"
#include "lock.h"
#include "malloc.h"
#include "os.h"

static struct malloc_state *init_user_state(char *tbase, size_t tsize) {
    size_t msize = pad_request(sizeof(struct malloc_state));
    struct malloc_chunk *heap = align_as_chunk(tbase);
    struct malloc_state *state = (struct malloc_state *) (chunk_to_mem(heap));
    memset(state, 0, msize);
    (void) INITIAL_LOCK(&state->mutex);
    heap->head = msize | INUSE_BITS;
    state->segment.base = state->least_addr = tbase;
    state->segment.size = state->footprint = state->max_footprint = tsize;
    state->magic = params.magic;
    state->release_checks = MAX_RELEASE_CHECK_RATE;
    state->flags = params.default_flags;
    disable_contiguous(state);
    init_bins(state);
    struct malloc_chunk *mn = next_chunk(mem_to_chunk(state));
    init_top(state, mn, (size_t) ((tbase + tsize) - (char *) mn) - TOP_FOOT_SIZE);
    check_top_chunk(state, state->top);
    return state;
}

dl_export dl_heap_t dl_create_heap(size_t capacity, int locked) {
    ensure_initialization();
    struct malloc_state *state = 0;
    size_t msize = pad_request(sizeof(struct malloc_state));
    if (capacity < (size_t) -(msize + TOP_FOOT_SIZE + params.page_size)) {
        size_t rs = capacity == 0
                    ? params.granularity
                    : capacity + TOP_FOOT_SIZE + msize;
        size_t tsize = granularity_align(rs);
        char *tbase = (char *) call_mmap(tsize);
        if (tbase != MFAIL) {
            state = init_user_state(tbase, tsize);
            state->segment.flags = USE_MMAP_BIT;
            set_lock(state, locked);
        }
    }
    return (dl_heap_t) state;
}

dl_export dl_heap_t dl_create_heap_with_base(void *base, size_t capacity, int locked) {
    ensure_initialization();
    struct malloc_state *state = 0;
    size_t msize = pad_request(sizeof(struct malloc_state));
    if (capacity > msize + TOP_FOOT_SIZE
        && capacity < (size_t) -(msize + TOP_FOOT_SIZE + params.page_size)) {
        state = init_user_state((char *) base, capacity);
        state->segment.flags = EXTERN_BIT;
        set_lock(state, locked);
    }
    return (dl_heap_t) state;
}

dl_export size_t dl_destroy_heap(dl_heap_t heap) {
    size_t freed = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        (void) DESTROY_LOCK(&state->mutex); /* destroy before unmapped */
        struct malloc_segment *segment = &state->segment;
        while (segment != 0) {
            if (is_mmapped_segment(segment) && !is_extern_segment(segment)) {
                if (call_munmap(segment->base, segment->size) == 0) {
                    freed += segment->size;
                }
            }
            segment = segment->next;
        }
    }
    else {
        usage_error(state, state);
    }
    return freed;
}

dl_export int dl_heap_track_large_chunks(dl_heap_t heap, int enable) {
    int ret = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!PREACTION(state)) {
        if (!use_mmap(state)) {
            ret = 1;
        }
        if (!enable) {
            enable_mmap(state);
        }
        else {
            disable_mmap(state);
        }
        POSTACTION(state);
    }
    return ret;
}

dl_export void *dl_heap_malloc(dl_heap_t heap, size_t bytes) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
        return 0;
    }
    return dl_malloc_impl(state, bytes);
}

dl_export void dl_heap_free(dl_heap_t heap, void *mem) {
    if (mem != 0) {
        struct malloc_chunk *p = mem_to_chunk(mem);
#if FOOTERS
        struct malloc_state *state = get_state_for(p);
        (void) heap; /* placate people compiling -Wunused */
#else /* FOOTERS */
        struct malloc_state *state = (struct malloc_state *) heap;
#endif /* FOOTERS */
        if (!ok_magic(state)) {
            usage_error(state, p);
            return;
        }
        dl_free_impl(state, p);
    }
}

dl_export void *dl_heap_calloc(dl_heap_t heap, size_t n_elements, size_t elem_size) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
        return 0;
    }
    size_t req = 0;
    if (n_elements != 0) {
        req = n_elements * elem_size;
        if (((n_elements | elem_size) & ~(size_t) 0xffff) && (req / n_elements != elem_size)) {
            req = MAX_SIZE_T; /* force downstream failure on overflow */
        }
    }
    void *mem = internal_malloc(state, req);
    if (mem != 0 && calloc_must_clear(mem_to_chunk(mem))) {
        memset(mem, 0, req);
    }
    return mem;
}

dl_export void *dl_heap_realloc(dl_heap_t heap, void *old_mem, size_t new_size) {
    void *mem = 0;
    if (old_mem == 0) {
        mem = dl_heap_malloc(heap, new_size);
    }
    else if (new_size >= MAX_REQUEST) {
        malloc_failure();
    }
#ifdef REALLOC_ZERO_BYTES_FREES
        else if (bytes == 0) {
            heap_free(heap, old_mem);
        }
#endif /* REALLOC_ZERO_BYTES_FREES */
    else {
        size_t nb = request_to_size(new_size);
        struct malloc_chunk *old_p = mem_to_chunk(old_mem);
#if !FOOTERS
        struct malloc_state *state = (struct malloc_state *) heap;
#else /* FOOTERS */
        struct malloc_state *state = get_state_for(old_p);
        if (!ok_magic(state)) {
            usage_error(state, old_mem);
            return 0;
        }
#endif /* FOOTERS */
        if (!PREACTION(state)) {
            struct malloc_chunk *new_p = try_realloc_chunk(state, old_p, nb, 1);
            POSTACTION(state);
            if (new_p != 0) {
                check_inuse_chunk(state, new_p);
                mem = chunk_to_mem(new_p);
            }
            else {
                mem = dl_heap_malloc(state, new_size);
                if (mem != 0) {
                    size_t oc = chunk_size(old_p) - overhead_for(old_p);
                    memcpy(mem, old_mem, (oc < new_size) ? oc : new_size);
                    dl_heap_free(state, old_mem);
                }
            }
        }
    }
    return mem;
}

dl_export void *dl_heap_realloc_in_place(dl_heap_t heap, void *old_mem, size_t new_size) {
    void *mem = 0;
    if (old_mem != 0) {
        if (new_size >= MAX_REQUEST) {
            malloc_failure();
        }
        else {
            size_t nb = request_to_size(new_size);
            struct malloc_chunk *old_p = mem_to_chunk(old_mem);
#if !FOOTERS
            struct malloc_state *state = (struct malloc_state *) heap;
#else /* FOOTERS */
            struct malloc_state *state = get_state_for(old_p);
            (void) heap; /* placate people compiling -Wunused */
            if (!ok_magic(state)) {
                usage_error(state, old_mem);
                return 0;
            }
#endif /* FOOTERS */
            if (!PREACTION(state)) {
                struct malloc_chunk *new_p = try_realloc_chunk(state, old_p, nb, 0);
                POSTACTION(state);
                if (new_p == old_p) {
                    check_inuse_chunk(state, new_p);
                    mem = old_mem;
                }
            }
        }
    }
    return mem;
}

dl_export void *dl_heap_memalign(dl_heap_t heap, size_t alignment, size_t bytes) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
        return 0;
    }
    if (alignment <= MALLOC_ALIGNMENT) {
        return dl_heap_malloc(heap, bytes);
    }
    return internal_memalign(state, alignment, bytes);
}

dl_export void **dl_heap_independent_calloc(dl_heap_t heap, size_t n_elements, size_t elem_size, void **chunks) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
        return 0;
    }
    size_t sz = elem_size; /* serves as 1-element array */
    return ialloc(state, n_elements, &sz, 3, chunks);
}

dl_export void **dl_heap_independent_comalloc(dl_heap_t heap, size_t n_elements, size_t *sizes, void **chunks) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
        return 0;
    }
    return ialloc(state, n_elements, sizes, 0, chunks);
}

dl_export size_t dl_heap_bulk_free(dl_heap_t heap, void **array, size_t n_elements) {
    return internal_bulk_free((struct malloc_state *) heap, array, n_elements);
}

dl_export int dl_heap_trim(dl_heap_t heap, size_t pad) {
    int result = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (!ok_magic(state)) {
        usage_error(state, state);
    }
    else {
        if (!PREACTION(state)) {
            result = sys_trim(state, pad);
            POSTACTION(state);
        }
    }
    return result;
}
