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

dl_export void *dl_malloc(size_t bytes) {
#if USE_LOCKS
    ensure_initialization(); /* initialize in sys_alloc if not using locks */
#endif
    return dl_malloc_impl(&global_malloc_state, bytes);
}

dl_export void dl_free(void *mem) {
    if (mem != 0) {
        struct malloc_chunk *p = mem_to_chunk(mem);
#if FOOTERS
        struct malloc_state *state = get_state_for(p);
        if (!ok_magic(state)) {
            usage_error(state, p);
            return;
        }
#else /* FOOTERS */
        struct malloc_state *state = &global_malloc_state;
#endif /* FOOTERS */
        dl_free_impl(state, p);
    }
}

dl_export void *dl_calloc(size_t n_elements, size_t elem_size) {
    size_t req = 0;
    if (n_elements != 0) {
        req = n_elements * elem_size;
        if (((n_elements | elem_size) & ~(size_t) 0xffff) && (req / n_elements != elem_size)) {
            req = MAX_SIZE_T; /* force downstream failure on overflow */
        }
    }
    void *mem = dl_malloc(req);
    if (mem != 0 && calloc_must_clear(mem_to_chunk(mem))) {
        memset(mem, 0, req);
    }
    return mem;
}

dl_export void *dl_realloc(void *old_mem, size_t bytes) {
    void *mem = 0;
    if (old_mem == 0) {
        mem = dl_malloc(bytes);
    }
    else if (bytes >= MAX_REQUEST) {
        malloc_failure();
    }
#ifdef REALLOC_ZERO_BYTES_FREES
        else if (bytes == 0) {
            dl_free(old_mem);
        }
#endif /* REALLOC_ZERO_BYTES_FREES */
    else {
        size_t nb = request_to_size(bytes);
        struct malloc_chunk *old_p = mem_to_chunk(old_mem);
#if !FOOTERS
        struct malloc_state *state = &global_malloc_state;
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
                mem = internal_malloc(state, bytes);
                if (mem != 0) {
                    size_t oc = chunk_size(old_p) - overhead_for(old_p);
                    memcpy(mem, old_mem, oc < bytes ? oc : bytes);
                    internal_free(state, old_mem);
                }
            }
        }
    }
    return mem;
}

dl_export void *dl_realloc_in_place(void *old_mem, size_t bytes) {
    void *mem = 0;
    if (old_mem != 0) {
        if (bytes >= MAX_REQUEST) {
            malloc_failure();
        }
        else {
            size_t nb = request_to_size(bytes);
            struct malloc_chunk *old_p = mem_to_chunk(old_mem);
#if !FOOTERS
            struct malloc_state *state = &global_malloc_state;
#else /* FOOTERS */
            struct malloc_state *state = get_state_for(old_p);
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

dl_export dl_export void *dl_memalign(size_t alignment, size_t bytes) {
    if (alignment <= MALLOC_ALIGNMENT) {
        return dl_malloc(bytes);
    }
    return internal_memalign(&global_malloc_state, alignment, bytes);
}

dl_export int dl_posix_memalign(void **pp, size_t alignment, size_t bytes) {
    void *mem = 0;
    if (alignment == MALLOC_ALIGNMENT) {
        mem = dl_malloc(bytes);
    }
    else {
        size_t d = alignment / sizeof(void *);
        size_t r = alignment % sizeof(void *);
        if (r != 0 || d == 0 || (d & (d - (size_t) 1)) != 0) {
            return EINVAL;
        }
        else if (bytes <= MAX_REQUEST - alignment) {
            if (alignment < MIN_CHUNK_SIZE) {
                alignment = MIN_CHUNK_SIZE;
            }
            mem = internal_memalign(&global_malloc_state, alignment, bytes);
        }
    }
    if (mem == 0) {
        return ENOMEM;
    }
    else {
        *pp = mem;
        return 0;
    }
}

dl_export void *dl_valloc(size_t bytes) {
    ensure_initialization();
    size_t page_size = params.page_size;
    return dl_memalign(page_size, bytes);
}

dl_export void *dl_pvalloc(size_t bytes) {
    ensure_initialization();
    size_t page_size = params.page_size;
    return dl_memalign(page_size, (bytes + page_size - (size_t) 1) & ~(page_size - (size_t) 1));
}

dl_export void **dl_independent_calloc(size_t n_elements, size_t elem_size, void **chunks) {
    size_t sz = elem_size; /* serves as 1-element array */
    return ialloc(&global_malloc_state, n_elements, &sz, 3, chunks);
}

dl_export void **dl_independent_comalloc(size_t n_elements, size_t *sizes, void **chunks) {
    return ialloc(&global_malloc_state, n_elements, sizes, 0, chunks);
}

dl_export size_t dl_bulk_free(void **array, size_t nelem) {
    return internal_bulk_free(&global_malloc_state, array, nelem);
}

dl_export int dl_malloc_trim(size_t pad) {
    int result = 0;
    ensure_initialization();
    if (!PREACTION(&global_malloc_state)) {
        result = sys_trim(&global_malloc_state, pad);
        POSTACTION(&global_malloc_state);
    }
    return result;
}

dl_export int dl_mallopt(int param_number, int value) {
    return change_param(param_number, value);
}

#if OVERRIDE

dl_export void *malloc(size_t size) DL_FORWARD_1(dl_malloc, size);

dl_export void *calloc(size_t num, size_t size) DL_FORWARD_2(dl_calloc, num, size);

dl_export void *realloc(void *p, size_t new_size) DL_FORWARD_2(dl_realloc, p, new_size);

dl_export void free(void *p) DL_FORWARD0_1(dl_free, p);

#endif /* OVERRIDE */
