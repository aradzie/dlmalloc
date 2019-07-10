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
#include "os.h"

dl_force_inline void *dl_malloc_impl(struct malloc_state *state, size_t bytes) {
    /*
       Basic algorithm:
       If a small request (< 256 bytes minus per-chunk overhead):
         1. If one exists, use a remainderless chunk in associated small_bin.
            (Remainderless means that there are too few excess bytes to
            represent as a chunk.)
         2. If it is big enough, use the dv chunk, which is normally the
            chunk adjacent to the one used for the most recent small request.
         3. If one exists, split the smallest available chunk in a bin,
            saving remainder in dv.
         4. If it is big enough, use the top chunk.
         5. If available, get memory from system and use it
       Otherwise, for a large request:
         1. Find the smallest available binned chunk that fits, and use it
            if it is better fitting than dv chunk, splitting if necessary.
         2. If better fitting than any binned chunk, use the dv chunk.
         3. If it is big enough, use the top chunk.
         4. If request size >= mmap threshold, try to directly mmap this chunk.
         5. If available, get memory from system and use it

       The ugly goto's here ensure that postaction occurs along all paths.
    */

    if (!PREACTION(state)) {
        void *mem;
        size_t nb;
        if (bytes <= MAX_SMALL_REQUEST) {
            bin_map_t small_bits;
            nb = (bytes < MIN_REQUEST) ? MIN_CHUNK_SIZE : pad_request(bytes);
            bin_index_t idx = small_index(nb);
            small_bits = state->small_map >> idx;

            if ((small_bits & 0x3U) != 0) { /* Remainderless fit to a small_bin. */
                idx += ~small_bits & 1;       /* Uses next bin if idx empty */
                struct malloc_chunk *b = small_bin_at(state, idx);
                struct malloc_chunk *p = b->fd;
                dl_assert(chunk_size(p) == small_index_to_size(idx));
                unlink_first_small_chunk(state, b, p, idx);
                set_inuse_and_prev_inuse(state, p, small_index_to_size(idx));
                mem = chunk_to_mem(p);
                check_malloced_chunk(state, mem, nb);
                goto postaction;
            }
            else if (nb > state->dv_size) {
                if (small_bits != 0) { /* Use chunk in next nonempty small_bin */
                    bin_index_t i;
                    bin_map_t left_bits = (small_bits << idx) & left_bits(index_to_bit(idx));
                    bin_map_t least_bit = least_bit(left_bits);
                    compute_bit2idx(least_bit, i);
                    struct malloc_chunk *b = small_bin_at(state, i);
                    struct malloc_chunk *p = b->fd;
                    dl_assert(chunk_size(p) == small_index_to_size(i));
                    unlink_first_small_chunk(state, b, p, i);
                    size_t rsize = small_index_to_size(i) - nb;
                    /* Fit here cannot be remainderless if 4byte sizes */
                    if (sizeof(size_t) != 4 && rsize < MIN_CHUNK_SIZE) {
                        set_inuse_and_prev_inuse(state, p, small_index_to_size(i));
                    }
                    else {
                        set_size_and_prev_inuse_of_inuse_chunk(state, p, nb);
                        struct malloc_chunk *r = chunk_plus_offset(p, nb);
                        set_size_and_prev_inuse_of_free_chunk(r, rsize);
                        replace_dv(state, r, rsize);
                    }
                    mem = chunk_to_mem(p);
                    check_malloced_chunk(state, mem, nb);
                    goto postaction;
                }
                else if (state->tree_map != 0 && (mem = tmalloc_small(state, nb)) != 0) {
                    check_malloced_chunk(state, mem, nb);
                    goto postaction;
                }
            }
        }
        else if (bytes >= MAX_REQUEST) {
            nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
        }
        else {
            nb = pad_request(bytes);
            if (state->tree_map != 0 && (mem = tmalloc_large(state, nb)) != 0) {
                check_malloced_chunk(state, mem, nb);
                goto postaction;
            }
        }

        if (nb <= state->dv_size) {
            size_t rsize = state->dv_size - nb;
            struct malloc_chunk *p = state->dv;
            if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
                struct malloc_chunk *r = state->dv = chunk_plus_offset(p, nb);
                state->dv_size = rsize;
                set_size_and_prev_inuse_of_free_chunk(r, rsize);
                set_size_and_prev_inuse_of_inuse_chunk(state, p, nb);
            }
            else { /* exhaust dv */
                size_t dvs = state->dv_size;
                state->dv_size = 0;
                state->dv = 0;
                set_inuse_and_prev_inuse(state, p, dvs);
            }
            mem = chunk_to_mem(p);
            check_malloced_chunk(state, mem, nb);
            goto postaction;
        }
        else if (nb < state->top_size) { /* Split top */
            size_t rsize = state->top_size -= nb;
            struct malloc_chunk *p = state->top;
            struct malloc_chunk *r = state->top = chunk_plus_offset(p, nb);
            r->head = rsize | PREV_INUSE_BIT;
            set_size_and_prev_inuse_of_inuse_chunk(state, p, nb);
            mem = chunk_to_mem(p);
            check_top_chunk(state, state->top);
            check_malloced_chunk(state, mem, nb);
            goto postaction;
        }

        mem = sys_alloc(state, nb);

        postaction:
        POSTACTION(state);
        return mem;
    }

    return 0;
}

dl_force_inline void dl_free_impl(struct malloc_state *state, struct malloc_chunk *p) {
    /*
       Consolidate freed chunks with preceding or succeeding bordering
       free chunks, if they exist, and then place in a bin.  Intermixed
       with special cases for top, dv, mmapped chunks, and usage errors.
    */

    if (!PREACTION(state)) {
        check_inuse_chunk(state, p);
        if (likely(ok_address(state, p) && ok_inuse(p))) {
            size_t psize = chunk_size(p);
            struct malloc_chunk *next = chunk_plus_offset(p, psize);
            if (!prev_inuse(p)) {
                size_t prev_size = p->prev_foot;
                if (is_mmapped(p)) {
                    psize += prev_size + MMAP_FOOT_PAD;
                    if (call_munmap((char *) p - prev_size, psize) == 0) {
                        state->footprint -= psize;
                    }
                    goto postaction;
                }
                else {
                    struct malloc_chunk *prev = chunk_minus_offset(p, prev_size);
                    psize += prev_size;
                    p = prev;
                    if (likely(ok_address(state, prev))) { /* consolidate backward */
                        if (p != state->dv) {
                            unlink_chunk(state, p, prev_size);
                        }
                        else if ((next->head & INUSE_BITS) == INUSE_BITS) {
                            state->dv_size = psize;
                            set_free_with_prev_inuse(p, psize, next);
                            goto postaction;
                        }
                    }
                    else {
                        goto erroraction;
                    }
                }
            }

            if (likely(ok_next(p, next) && ok_prev_inuse(next))) {
                if (!curr_inuse(next)) {  /* consolidate forward */
                    if (next == state->top) {
                        size_t tsize = state->top_size += psize;
                        state->top = p;
                        p->head = tsize | PREV_INUSE_BIT;
                        if (p == state->dv) {
                            state->dv = 0;
                            state->dv_size = 0;
                        }
                        if (should_trim(state, tsize)) {
                            sys_trim(state, 0);
                        }
                        goto postaction;
                    }
                    else if (next == state->dv) {
                        size_t dsize = state->dv_size += psize;
                        state->dv = p;
                        set_size_and_prev_inuse_of_free_chunk(p, dsize);
                        goto postaction;
                    }
                    else {
                        size_t nsize = chunk_size(next);
                        psize += nsize;
                        unlink_chunk(state, next, nsize);
                        set_size_and_prev_inuse_of_free_chunk(p, psize);
                        if (p == state->dv) {
                            state->dv_size = psize;
                            goto postaction;
                        }
                    }
                }
                else {
                    set_free_with_prev_inuse(p, psize, next);
                }

                if (is_small(psize)) {
                    insert_small_chunk(state, p, psize);
                    check_free_chunk(state, p);
                }
                else {
                    struct malloc_tree_chunk *tp = (struct malloc_tree_chunk *) p;
                    insert_large_chunk(state, tp, psize);
                    check_free_chunk(state, p);
                    if (--state->release_checks == 0) {
                        release_unused_segments(state);
                    }
                }
                goto postaction;
            }
        }
        erroraction:
        usage_error(state, p);
        postaction:
        POSTACTION(state);
    }
}

/* allocate a large request from the best fitting chunk in a tree_bin */
void *tmalloc_large(struct malloc_state *state, size_t nb) {
    struct malloc_tree_chunk *v = 0;
    size_t rsize = -nb; /* Unsigned negation */
    struct malloc_tree_chunk *t;
    bin_index_t idx;
    compute_tree_index(nb, idx);
    if ((t = *tree_bin_at(state, idx)) != 0) {
        /* Traverse tree for this bin looking for node with size == nb */
        size_t sizebits = nb << leftshift_for_tree_index(idx);
        struct malloc_tree_chunk *rst = 0;  /* The deepest untaken right subtree */
        for (;;) {
            struct malloc_tree_chunk *rt;
            size_t trem = chunk_size(t) - nb;
            if (trem < rsize) {
                v = t;
                if ((rsize = trem) == 0) {
                    break;
                }
            }
            rt = t->child[1];
            t = t->child[(sizebits >> (SIZE_T_BITSIZE - (size_t) 1)) & 1];
            if (rt != 0 && rt != t) {
                rst = rt;
            }
            if (t == 0) {
                t = rst; /* set t to least subtree holding sizes > nb */
                break;
            }
            sizebits <<= 1;
        }
    }
    if (t == 0 && v == 0) { /* set t to root of next non-empty tree_bin */
        bin_map_t left_bits = left_bits(index_to_bit(idx)) & state->tree_map;
        if (left_bits != 0) {
            bin_index_t i;
            bin_map_t least_bit = least_bit(left_bits);
            compute_bit2idx(least_bit, i);
            t = *tree_bin_at(state, i);
        }
    }

    while (t != 0) { /* find smallest of tree or subtree */
        size_t trem = chunk_size(t) - nb;
        if (trem < rsize) {
            rsize = trem;
            v = t;
        }
        t = leftmost_child(t);
    }

    /*  If dv is a better fit, return 0 so malloc will use it */
    if (v != 0 && rsize < (size_t) (state->dv_size - nb)) {
        if (likely(ok_address(state, v))) { /* split */
            struct malloc_chunk *r = chunk_plus_offset(v, nb);
            dl_assert(chunk_size(v) == rsize + nb);
            if (likely(ok_next(v, r))) {
                unlink_large_chunk(state, v);
                if (rsize < MIN_CHUNK_SIZE) {
                    set_inuse_and_prev_inuse(state, v, (rsize + nb));
                }
                else {
                    set_size_and_prev_inuse_of_inuse_chunk(state, v, nb);
                    set_size_and_prev_inuse_of_free_chunk(r, rsize);
                    insert_chunk(state, r, rsize);
                }
                return chunk_to_mem(v);
            }
        }
        corruption_error(state);
    }
    return 0;
}

/* allocate a small request from the best fitting chunk in a tree_bin */
void *tmalloc_small(struct malloc_state *state, size_t nb) {
    struct malloc_tree_chunk *t, *v;
    bin_index_t i;
    bin_map_t least_bit = least_bit(state->tree_map);
    compute_bit2idx(least_bit, i);
    v = t = *tree_bin_at(state, i);
    size_t rsize = chunk_size(t) - nb;

    while ((t = leftmost_child(t)) != 0) {
        size_t trem = chunk_size(t) - nb;
        if (trem < rsize) {
            rsize = trem;
            v = t;
        }
    }

    if (likely(ok_address(state, v))) {
        struct malloc_chunk *r = chunk_plus_offset(v, nb);
        dl_assert(chunk_size(v) == rsize + nb);
        if (likely(ok_next(v, r))) {
            unlink_large_chunk(state, v);
            if (rsize < MIN_CHUNK_SIZE) {
                set_inuse_and_prev_inuse(state, v, (rsize + nb));
            }
            else {
                set_size_and_prev_inuse_of_inuse_chunk(state, v, nb);
                set_size_and_prev_inuse_of_free_chunk(r, rsize);
                replace_dv(state, r, rsize);
            }
            return chunk_to_mem(v);
        }
    }

    corruption_error(state);
    return 0;
}

/* Try to realloc; only in-place unless can_move true */
struct malloc_chunk *try_realloc_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t nb, int can_move) {
    struct malloc_chunk *new_p = 0;
    size_t old_size = chunk_size(chunk);
    struct malloc_chunk *next = chunk_plus_offset(chunk, old_size);
    if (likely(ok_address(state, chunk) && ok_inuse(chunk) && ok_next(chunk, next) && ok_prev_inuse(next))) {
        if (is_mmapped(chunk)) {
            new_p = mmap_resize(state, chunk, nb, can_move);
        }
        else if (old_size >= nb) {             /* already big enough */
            size_t rsize = old_size - nb;
            if (rsize >= MIN_CHUNK_SIZE) {      /* split off remainder */
                struct malloc_chunk *r = chunk_plus_offset(chunk, nb);
                set_inuse(state, chunk, nb);
                set_inuse(state, r, rsize);
                dispose_chunk(state, r, rsize);
            }
            new_p = chunk;
        }
        else if (next == state->top) {  /* extend into top */
            if (old_size + state->top_size > nb) {
                size_t new_size = old_size + state->top_size;
                size_t new_top_size = new_size - nb;
                struct malloc_chunk *new_top = chunk_plus_offset(chunk, nb);
                set_inuse(state, chunk, nb);
                new_top->head = new_top_size | PREV_INUSE_BIT;
                state->top = new_top;
                state->top_size = new_top_size;
                new_p = chunk;
            }
        }
        else if (next == state->dv) { /* extend into dv */
            size_t dvs = state->dv_size;
            if (old_size + dvs >= nb) {
                size_t dsize = old_size + dvs - nb;
                if (dsize >= MIN_CHUNK_SIZE) {
                    struct malloc_chunk *r = chunk_plus_offset(chunk, nb);
                    struct malloc_chunk *n = chunk_plus_offset(r, dsize);
                    set_inuse(state, chunk, nb);
                    set_size_and_prev_inuse_of_free_chunk(r, dsize);
                    clear_prev_inuse(n);
                    state->dv_size = dsize;
                    state->dv = r;
                }
                else { /* exhaust dv */
                    size_t new_size = old_size + dvs;
                    set_inuse(state, chunk, new_size);
                    state->dv_size = 0;
                    state->dv = 0;
                }
                new_p = chunk;
            }
        }
        else if (!curr_inuse(next)) { /* extend into next free chunk */
            size_t next_size = chunk_size(next);
            if (old_size + next_size >= nb) {
                size_t rsize = old_size + next_size - nb;
                unlink_chunk(state, next, next_size);
                if (rsize < MIN_CHUNK_SIZE) {
                    size_t new_size = old_size + next_size;
                    set_inuse(state, chunk, new_size);
                }
                else {
                    struct malloc_chunk *r = chunk_plus_offset(chunk, nb);
                    set_inuse(state, chunk, nb);
                    set_inuse(state, r, rsize);
                    dispose_chunk(state, r, rsize);
                }
                new_p = chunk;
            }
        }
    }
    else {
        usage_error(state, chunk_to_mem(chunk));
    }
    return new_p;
}

void *internal_memalign(struct malloc_state *state, size_t alignment, size_t bytes) {
    void *mem = 0;
    if (alignment < MIN_CHUNK_SIZE) { /* must be at least a minimum chunk size */
        alignment = MIN_CHUNK_SIZE;
    }
    if ((alignment & (alignment - (size_t) 1)) != 0) {/* Ensure a power of 2 */
        size_t a = MALLOC_ALIGNMENT << 1;
        while (a < alignment) {
            a <<= 1;
        }
        alignment = a;
    }
    if (bytes >= MAX_REQUEST - alignment) {
        if (state != 0) { /* Test isn't needed but avoids compiler warning */
            malloc_failure();
        }
    }
    else {
        size_t nb = request_to_size(bytes);
        size_t req = nb + alignment + MIN_CHUNK_SIZE - CHUNK_OVERHEAD;
        mem = internal_malloc(state, req);
        if (mem != 0) {
            struct malloc_chunk *p = mem_to_chunk(mem);
            if (PREACTION(state)) {
                return 0;
            }
            if ((((size_t) mem) & (alignment - 1)) != 0) { /* misaligned */
                /*
                  Find an aligned spot inside chunk.  Since we need to give
                  back leading space in a chunk of at least MIN_CHUNK_SIZE, if
                  the first calculation places us at a spot with less than
                  MIN_CHUNK_SIZE leader, we can move to the next aligned spot.
                  We've allocated enough total room so that this is always
                  possible.
                */
                char *br = (char *) mem_to_chunk(
                        (void *) (((size_t) ((char *) mem + alignment - (size_t) 1)) & -alignment));
                char *pos = (size_t) (br - (char *) p) >= MIN_CHUNK_SIZE
                            ? br : br + alignment;
                struct malloc_chunk *new_p = (struct malloc_chunk *) pos;
                size_t lead_size = pos - (char *) p;
                size_t new_size = chunk_size(p) - lead_size;

                if (is_mmapped(p)) { /* For mmapped chunks, just adjust offset */
                    new_p->prev_foot = p->prev_foot + lead_size;
                    new_p->head = new_size;
                }
                else { /* Otherwise, give back leader, use the rest */
                    set_inuse(state, new_p, new_size);
                    set_inuse(state, p, lead_size);
                    dispose_chunk(state, p, lead_size);
                }
                p = new_p;
            }

            /* Give back spare room at the end */
            if (!is_mmapped(p)) {
                size_t size = chunk_size(p);
                if (size > nb + MIN_CHUNK_SIZE) {
                    size_t remainder_size = size - nb;
                    struct malloc_chunk *remainder = chunk_plus_offset(p, nb);
                    set_inuse(state, p, nb);
                    set_inuse(state, remainder, remainder_size);
                    dispose_chunk(state, remainder, remainder_size);
                }
            }

            mem = chunk_to_mem(p);
            dl_assert (chunk_size(p) >= nb);
            dl_assert(((size_t) mem & (alignment - 1)) == 0);
            check_inuse_chunk(state, p);
            POSTACTION(state);
        }
    }
    return mem;
}

/*
  Common support for independent_X routines, handling
    all of the combinations that can result.
  The opts arg has:
    bit 0 set if all elements are same size (using sizes[0])
    bit 1 set if elements should be zeroed
*/
void **ialloc(struct malloc_state *state, size_t n_elements, size_t *sizes, int opts, void *chunks[]) {
    size_t element_size;   /* chunk_size of each element, if all same */
    size_t contents_size;  /* total size of elements */
    size_t array_size;     /* request size of pointer array */
    void *mem;             /* malloced aggregate space */
    struct malloc_chunk *p;              /* corresponding chunk */
    size_t remainder_size; /* remaining bytes while splitting */
    void **marray;         /* either "chunks" or malloced ptr array */
    struct malloc_chunk *array_chunk;    /* chunk for malloced ptr array */
    flag_t was_enabled;    /* to disable mmap */
    size_t size;
    size_t i;

    ensure_initialization();
    /* compute array length, if needed */
    if (chunks != 0) {
        if (n_elements == 0) {
            return chunks;
        } /* nothing to do */
        marray = chunks;
        array_size = 0;
    }
    else {
        /* if empty req, must still return chunk representing empty array */
        if (n_elements == 0) {
            return (void **) internal_malloc(state, 0);
        }
        marray = 0;
        array_size = request_to_size(n_elements * (sizeof(void *)));
    }

    /* compute total element size */
    if (opts & 0x1) { /* all-same-size */
        element_size = request_to_size(*sizes);
        contents_size = n_elements * element_size;
    }
    else { /* add up all the sizes */
        element_size = 0;
        contents_size = 0;
        for (i = 0; i != n_elements; ++i) {
            contents_size += request_to_size(sizes[i]);
        }
    }

    size = contents_size + array_size;

    /*
       Allocate the aggregate chunk.  First disable direct-mmapping so
       malloc won't use it, since we would not be able to later
       free/realloc space internal to a segregated mmap region.
    */
    was_enabled = use_mmap(state);
    disable_mmap(state);
    mem = internal_malloc(state, size - CHUNK_OVERHEAD);
    if (was_enabled) {
        enable_mmap(state);
    }
    if (mem == 0) {
        return 0;
    }

    if (PREACTION(state)) {
        return 0;
    }
    p = mem_to_chunk(mem);
    remainder_size = chunk_size(p);

    dl_assert(!is_mmapped(p));

    if (opts & 0x2) {       /* optionally clear the elements */
        memset((size_t *) mem, 0, remainder_size - sizeof(size_t) - array_size);
    }

    /* If not provided, allocate the pointer array as final part of chunk */
    if (marray == 0) {
        size_t array_chunk_size;
        array_chunk = chunk_plus_offset(p, contents_size);
        array_chunk_size = remainder_size - contents_size;
        marray = (void **) (chunk_to_mem(array_chunk));
        set_size_and_prev_inuse_of_inuse_chunk(state, array_chunk, array_chunk_size);
        remainder_size = contents_size;
    }

    /* split out elements */
    for (i = 0;; ++i) {
        marray[i] = chunk_to_mem(p);
        if (i != n_elements - 1) {
            if (element_size != 0) {
                size = element_size;
            }
            else {
                size = request_to_size(sizes[i]);
            }
            remainder_size -= size;
            set_size_and_prev_inuse_of_inuse_chunk(state, p, size);
            p = chunk_plus_offset(p, size);
        }
        else { /* the final element absorbs any overallocation slop */
            set_size_and_prev_inuse_of_inuse_chunk(state, p, remainder_size);
            break;
        }
    }

#if DEBUG
    if (marray != chunks) {
        /* final element must have exactly exhausted chunk */
        if (element_size != 0) {
            dl_assert(remainder_size == element_size);
        }
        else {
            dl_assert(remainder_size == request_to_size(sizes[i]));
        }
        check_inuse_chunk(state, mem_to_chunk(marray));
    }
    for (i = 0; i != n_elements; ++i) {
        check_inuse_chunk(state, mem_to_chunk(marray[i]));
    }

#endif /* DEBUG */

    POSTACTION(state);
    return marray;
}

/* Try to free all pointers in the given array.
   Note: this could be made faster, by delaying consolidation,
   at the price of disabling some user integrity checks, We
   still optimize some consolidations by combining adjacent
   chunks before freeing, which will occur often if allocated
   with ialloc or the array is sorted.
*/
size_t internal_bulk_free(struct malloc_state *state, void *array[], size_t nelem) {
    size_t unfreed = 0;
    if (!PREACTION(state)) {
        void **a;
        void **fence = &(array[nelem]);
        for (a = array; a != fence; ++a) {
            void *mem = *a;
            if (mem != 0) {
                struct malloc_chunk *p = mem_to_chunk(mem);
                size_t p_size = chunk_size(p);
#if FOOTERS
                if (get_state_for(p) != state) {
                    ++unfreed;
                    continue;
                }
#endif
                check_inuse_chunk(state, p);
                *a = 0;
                if (likely(ok_address(state, p) && ok_inuse(p))) {
                    void **b = a + 1; /* try to merge with next chunk */
                    struct malloc_chunk *next = next_chunk(p);
                    if (b != fence && *b == chunk_to_mem(next)) {
                        size_t new_size = chunk_size(next) + p_size;
                        set_inuse(state, p, new_size);
                        *b = chunk_to_mem(p);
                    }
                    else {
                        dispose_chunk(state, p, p_size);
                    }
                }
                else {
                    corruption_error(state);
                    break;
                }
            }
        }
        if (should_trim(state, state->top_size)) {
            sys_trim(state, 0);
        }
        POSTACTION(state);
    }
    return unfreed;
}
