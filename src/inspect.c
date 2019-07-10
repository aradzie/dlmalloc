#include <stdint.h>
#include <stdio.h>

#include "check.h"
#include "config.h"
#include "debug.h"
#include "error.h"
#include "init.h"
#include "lock.h"
#include "log.h"
#include "malloc.h"
#include "os.h"
#include "segment.h"
#include "state.h"

static struct mallinfo internal_mallinfo(struct malloc_state *state) {
    struct mallinfo mallinfo = {
            .arena = 0,
            .ordblks = 0,
            .smblks = 0,
            .hblks = 0,
            .hblkhd = 0,
            .usmblks = 0,
            .fsmblks = 0,
            .uordblks = 0,
            .fordblks = 0,
            .keepcost = 0,
    };
    ensure_initialization();
    if (!PREACTION(state)) {
        check_malloc_state(state);
        if (is_initialized(state)) {
            size_t nfree = (size_t) 1; /* top always free */
            size_t mfree = state->top_size + TOP_FOOT_SIZE;
            size_t sum = mfree;
            struct malloc_segment *segment = &state->segment;
            while (segment != 0) {
                struct malloc_chunk *chunk = align_as_chunk(segment->base);
                while (segment_holds(segment, chunk) && chunk != state->top && chunk->head != FENCEPOST_HEAD) {
                    size_t sz = chunk_size(chunk);
                    sum += sz;
                    if (!is_inuse(chunk)) {
                        mfree += sz;
                        ++nfree;
                    }
                    chunk = next_chunk(chunk);
                }
                segment = segment->next;
            }

            mallinfo.arena = sum;
            mallinfo.ordblks = nfree;
            mallinfo.hblkhd = state->footprint - sum;
            mallinfo.usmblks = state->max_footprint;
            mallinfo.uordblks = state->footprint - mfree;
            mallinfo.fordblks = mfree;
            mallinfo.keepcost = state->top_size;
        }

        POSTACTION(state);
    }
    return mallinfo;
}

dl_export struct mallinfo dl_mallinfo(void) {
    return internal_mallinfo(&global_malloc_state);
}

static void internal_malloc_stats(struct malloc_state *state) {
    ensure_initialization();
    if (!PREACTION(state)) {
        size_t max_footprint = 0;
        size_t footprint = 0;
        size_t used = 0;
        check_malloc_state(state);
        if (is_initialized(state)) {
            struct malloc_segment *segment = &state->segment;
            max_footprint = state->max_footprint;
            footprint = state->footprint;
            used = footprint - (state->top_size + TOP_FOOT_SIZE);
            while (segment != 0) {
                struct malloc_chunk *chunk = align_as_chunk(segment->base);
                while (segment_holds(segment, chunk) && chunk != state->top && chunk->head != FENCEPOST_HEAD) {
                    if (!is_inuse(chunk)) {
                        used -= chunk_size(chunk);
                    }
                    chunk = next_chunk(chunk);
                }
                segment = segment->next;
            }
        }
        POSTACTION(state); /* drop lock */
        dl_fprintf(stderr, "max system bytes = %10lu\n", (unsigned long) (max_footprint));
        dl_fprintf(stderr, "system bytes     = %10lu\n", (unsigned long) (footprint));
        dl_fprintf(stderr, "in use bytes     = %10lu\n", (unsigned long) (used));
    }
}

dl_export void dl_malloc_stats() {
    internal_malloc_stats(&global_malloc_state);
}

dl_export void dl_heap_malloc_stats(dl_heap_t heap) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        internal_malloc_stats(state);
    }
    else {
        usage_error(state, state);
    }
}

static void internal_inspect_all(
        struct malloc_state *state,
        void(*handler)(void *start, void *end, size_t used_bytes, void *callback_arg),
        void *arg
) {
    if (is_initialized(state)) {
        struct malloc_chunk *top = state->top;
        struct malloc_segment *segment = &state->segment;
        while (segment != 0) {
            struct malloc_chunk *chunk = align_as_chunk(segment->base);
            while (segment_holds(segment, chunk) && chunk->head != FENCEPOST_HEAD) {
                struct malloc_chunk *next = next_chunk(chunk);
                size_t size = chunk_size(chunk);
                size_t used;
                void *start;
                if (is_inuse(chunk)) {
                    used = size - CHUNK_OVERHEAD; /* must not be mmapped */
                    start = chunk_to_mem(chunk);
                }
                else {
                    used = 0;
                    if (is_small(size)) {     /* offset by possible bookkeeping */
                        start = (void *) ((char *) chunk + sizeof(struct malloc_chunk));
                    }
                    else {
                        start = (void *) ((char *) chunk + sizeof(struct malloc_tree_chunk));
                    }
                }
                if (start < (void *) next) {  /* skip if all space is bookkeeping */
                    handler(start, next, used, arg);
                }
                if (chunk == top) {
                    break;
                }
                chunk = next;
            }
            segment = segment->next;
        }
    }
}

dl_export void dl_malloc_inspect_all(
        void(*handler)(void *start, void *end, size_t used_bytes, void *callback_arg),
        void *arg
) {
    ensure_initialization();
    if (!PREACTION(&global_malloc_state)) {
        internal_inspect_all(&global_malloc_state, handler, arg);
        POSTACTION(&global_malloc_state);
    }
}

dl_export void dl_heap_inspect_all(
        dl_heap_t heap,
        void(*handler)(void *start, void *end, size_t used_bytes, void *callback_arg),
        void *arg
) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        if (!PREACTION(state)) {
            internal_inspect_all(state, handler, arg);
            POSTACTION(state);
        }
    }
    else {
        usage_error(state, state);
    }
}

dl_export size_t dl_malloc_footprint(void) {
    return global_malloc_state.footprint;
}

dl_export size_t dl_malloc_max_footprint(void) {
    return global_malloc_state.max_footprint;
}

dl_export size_t dl_malloc_footprint_limit(void) {
    if (global_malloc_state.footprint_limit == 0) {
        return MAX_SIZE_T;
    }
    else {
        return global_malloc_state.footprint_limit;
    }
}

dl_export size_t dl_malloc_set_footprint_limit(size_t bytes) {
    size_t result;  /* invert sense of 0 */
    if (bytes == 0) {
        result = granularity_align(1); /* Use minimal size */
    }
    if (bytes == MAX_SIZE_T) {
        result = 0; /* disable */
    }
    else {
        result = granularity_align(bytes);
    }
    return global_malloc_state.footprint_limit = result;
}

dl_export size_t dl_malloc_usable_size(const void *mem) {
    if (mem != 0) {
        struct malloc_chunk *p = mem_to_chunk((void *) mem);
        if (is_inuse(p)) {
            return chunk_size(p) - overhead_for(p);
        }
    }
    return 0;
}

dl_export size_t dl_heap_footprint(dl_heap_t heap) {
    size_t result = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        result = state->footprint;
    }
    else {
        usage_error(state, state);
    }
    return result;
}

dl_export size_t dl_heap_max_footprint(dl_heap_t heap) {
    size_t result = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        result = state->max_footprint;
    }
    else {
        usage_error(state, state);
    }
    return result;
}

dl_export size_t dl_heap_footprint_limit(dl_heap_t heap) {
    size_t result = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        size_t maf = state->footprint_limit;
        result = (maf == 0) ? MAX_SIZE_T : maf;
    }
    else {
        usage_error(state, state);
    }
    return result;
}

dl_export size_t dl_heap_set_footprint_limit(dl_heap_t heap, size_t bytes) {
    size_t result = 0;
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        if (bytes == 0) {
            result = granularity_align(1); /* Use minimal size */
        }
        if (bytes == MAX_SIZE_T) {
            result = 0; /* disable */
        }
        else {
            result = granularity_align(bytes);
        }
        state->footprint_limit = result;
    }
    else {
        usage_error(state, state);
    }
    return result;
}

dl_export size_t dl_heap_usable_size(const void *mem) {
    if (mem != 0) {
        struct malloc_chunk *p = mem_to_chunk((void *) mem);
        if (is_inuse(p)) {
            return chunk_size(p) - overhead_for(p);
        }
    }
    return 0;
}

#ifdef DEBUG

static void internal_print_allocations(struct malloc_state *state) {
    ensure_initialization();
    if (!PREACTION(state)) {
        check_malloc_state(state);
        if (is_initialized(state)) {
            struct malloc_segment *segment = &state->segment;
            while (segment != 0) {
                dl_printf(
                        "segment=0x%016lX "
                        "base=0x%016lX "
                        "size=%10lu "
                        "mmapped=%d "
                        "extern=%d\n",
                        (uintptr_t) segment,
                        (uintptr_t) segment->base,
                        segment->size,
                        is_mmapped_segment(segment),
                        is_extern_segment(segment));
                struct malloc_chunk *chunk = align_as_chunk(segment->base);
                while (segment_holds(segment, chunk) /*&& chunk != state->top*/ && chunk->head != FENCEPOST_HEAD) {
                    dl_printf(
                            "chunk=0x%016lX "
                            "size=%10lu "
                            "inuse=%d "
                            "mmapped=%d\n",
                            (uintptr_t) chunk,
                            chunk_size(chunk),
                            is_inuse(chunk),
                            is_mmapped(chunk));
                    chunk = next_chunk(chunk);
                }
                segment = segment->next;
            }
        }
        POSTACTION(state); /* drop lock */
    }
}

dl_export void dl_print_allocations() {
    internal_print_allocations(&global_malloc_state);
}

dl_export void dl_heap_print_allocations(dl_heap_t heap) {
    struct malloc_state *state = (struct malloc_state *) heap;
    if (ok_magic(state)) {
        internal_print_allocations(state);
    }
    else {
        usage_error(state, state);
    }
}

#endif /* DEBUG */

#ifdef DEBUG

#if defined(__GNUC__) || defined(__clang__)
__attribute__((destructor))
#endif
void on_exit() {
    dl_malloc_stats();
}

#endif
