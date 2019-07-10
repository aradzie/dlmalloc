#include <unistd.h>         /* for sbrk, sysconf */
#include <time.h>           /* for magic initialization */
#include <stdlib.h>

#include "malloc.h"
#include "init.h"
#include "lock.h"

struct malloc_params params;

/* The global malloc_state used for all non-"dl_heap_t" calls */
struct malloc_state global_malloc_state;

/* Initialize params */
int init_params(void) {
    ACQUIRE_MALLOC_GLOBAL_LOCK();
    if (params.magic == 0) {
        size_t psize = sysconf(_SC_PAGE_SIZE);
        size_t gsize = DEFAULT_GRANULARITY != 0 ? DEFAULT_GRANULARITY : psize;

        /* Sanity-check configuration:
           size_t must be unsigned and as wide as pointer type.
           ints must be at least 4 bytes.
           alignment must be at least 8.
           Alignment, min chunk size, and page size must all be powers of 2.
        */
        if ((sizeof(size_t) != sizeof(char *))
            || (MAX_SIZE_T < MIN_CHUNK_SIZE)
            || (sizeof(int) < 4)
            || (MALLOC_ALIGNMENT < (size_t) 8U)
            || ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT - (size_t) 1)) != 0)
            || ((MALLOC_CHUNK_SIZE & (MALLOC_CHUNK_SIZE - (size_t) 1)) != 0)
            || ((gsize & (gsize - (size_t) 1)) != 0)
            || ((psize & (psize - (size_t) 1)) != 0)) {
            abort();
        }
        params.granularity = gsize;
        params.page_size = psize;
        params.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
        params.trim_threshold = DEFAULT_TRIM_THRESHOLD;
#if MORECORE_CONTIGUOUS
        params.default_flags = USE_LOCK_BIT | USE_MMAP_BIT;
#else  /* MORECORE_CONTIGUOUS */
        params.default_flags = USE_LOCK_BIT | USE_MMAP_BIT | USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */
        /* Set up lock for main malloc area */
        global_malloc_state.flags = params.default_flags;
        (void) INITIAL_LOCK(&global_malloc_state.mutex);
#if LOCK_AT_FORK
        pthread_atfork(&pre_fork, &post_fork_parent, &post_fork_child);
#endif

        size_t magic = (size_t) (time(0) ^ (size_t) 0x55555555U);
        magic |= (size_t) 8U;    /* ensure nonzero */
        magic &= ~(size_t) 7U;   /* improve chances of fault for bad values */
        /* Until memory modes commonly available, use volatile-write */
        (*(volatile size_t *) (&(params.magic))) = magic;
    }

    RELEASE_MALLOC_GLOBAL_LOCK();
    return 1;
}

/* support for mallopt */
int change_param(int param_number, int value) {
    ensure_initialization();
    size_t val = value == -1 ? MAX_SIZE_T : (size_t) value;
    switch (param_number) {
        case M_TRIM_THRESHOLD:
            params.trim_threshold = val;
            return 1;
        case M_GRANULARITY:
            if (val >= params.page_size && (val & (val - 1)) == 0) {
                params.granularity = val;
                return 1;
            }
            else {
                return 0;
            }
        case M_MMAP_THRESHOLD:
            params.mmap_threshold = val;
            return 1;
        default:
            return 0;
    }
}
