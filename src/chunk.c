#include <stdlib.h>

#include "assert.h"
#include "check.h"
#include "chunk.h"
#include "config.h"
#include "debug.h"
#include "error.h"
#include "os.h"
#include "segment.h"
#include "state.h"

/* Relays to large vs small bin operations */
void insert_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    if (is_small(size)) {
        insert_small_chunk(state, chunk, size);
    }
    else {
        insert_large_chunk(state, (struct malloc_tree_chunk *) chunk, size);
    }
}

void unlink_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    if (is_small(size)) {
        unlink_small_chunk(state, chunk, size);
    }
    else {
        unlink_large_chunk(state, (struct malloc_tree_chunk *) chunk);
    }
}

/* Link a free chunk into a small_bin  */
void insert_small_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    bin_index_t index = small_index(size);
    struct malloc_chunk *b = small_bin_at(state, index);
    struct malloc_chunk *f = b;
    dl_assert(size >= MIN_CHUNK_SIZE);
    if (!small_map_is_marked(state, index)) {
        mark_small_map(state, index);
    }
    else if (likely(ok_address(state, b->fd))) {
        f = b->fd;
    }
    else {
        corruption_error(state);
    }
    b->fd = chunk;
    f->bk = chunk;
    chunk->fd = f;
    chunk->bk = b;
}

/* Unlink a chunk from a small_bin  */
void unlink_small_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    struct malloc_chunk *f = chunk->fd;
    struct malloc_chunk *b = chunk->bk;
    bin_index_t I = small_index(size);
    dl_assert(chunk != b);
    dl_assert(chunk != f);
    dl_assert(chunk_size(chunk) == small_index_to_size(I));
    if (likely(f == small_bin_at(state, I) || (ok_address(state, f) && f->bk == chunk))) {
        if (b == f) {
            clear_small_map(state, I);
        }
        else if (likely(b == small_bin_at(state, I) || (ok_address(state, b) && b->fd == chunk))) {
            f->bk = b;
            b->fd = f;
        }
        else {
            corruption_error(state);
        }
    }
    else {
        corruption_error(state);
    }
}

/* Unlink the first chunk from a small_bin */
void unlink_first_small_chunk(struct malloc_state *state, struct malloc_chunk *b, struct malloc_chunk *chunk, bin_index_t index) {
    struct malloc_chunk *f = chunk->fd;
    dl_assert(chunk != b);
    dl_assert(chunk != f);
    dl_assert(chunk_size(chunk) == small_index_to_size(index));
    if (b == f) {
        clear_small_map(state, index);
    }
    else if (likely(ok_address(state, f) && f->bk == chunk)) {
        f->bk = b;
        b->fd = f;
    }
    else {
        corruption_error(state);
    }
}

/* Replace dv node, binning the old one */
/* Used only when dv_size known to be small */
void replace_dv(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    size_t dv_size = state->dv_size;
    dl_assert(is_small(dv_size));
    if (dv_size != 0) {
        insert_small_chunk(state, state->dv, dv_size);
    }
    state->dv_size = size;
    state->dv = chunk;
}

/* Insert chunk into tree */
void insert_large_chunk(struct malloc_state *state, struct malloc_tree_chunk *chunk, size_t size) {
    struct malloc_tree_chunk **H;
    bin_index_t I;
    compute_tree_index(size, I);
    H = tree_bin_at(state, I);
    chunk->index = I;
    chunk->child[0] = chunk->child[1] = 0;
    if (!tree_map_is_marked(state, I)) {
        mark_tree_map(state, I);
        *H = chunk;
        chunk->parent = (struct malloc_tree_chunk *) H;
        chunk->fd = chunk->bk = chunk;
    }
    else {
        struct malloc_tree_chunk *T = *H;
        size_t K = size << leftshift_for_tree_index(I);
        for (;;) {
            if (chunk_size(T) != size) {
                struct malloc_tree_chunk **C = &(T->child[(K >> (SIZE_T_BITSIZE - (size_t) 1)) & 1]);
                K <<= 1;
                if (*C != 0) {
                    T = *C;
                }
                else if (likely(ok_address(state, C))) {
                    *C = chunk;
                    chunk->parent = T;
                    chunk->fd = chunk->bk = chunk;
                    break;
                }
                else {
                    corruption_error(state);
                    break;
                }
            }
            else {
                struct malloc_tree_chunk *F = T->fd;
                if (likely(ok_address(state, T) && ok_address(state, F))) {
                    T->fd = F->bk = chunk;
                    chunk->fd = F;
                    chunk->bk = T;
                    chunk->parent = 0;
                    break;
                }
                else {
                    corruption_error(state);
                    break;
                }
            }
        }
    }
}

/*
  Unlink steps:

  1. If x is a chained node, unlink it from its same-sized fd/bk links
     and choose its bk node as its replacement.
  2. If x was the last node of its size, but not a leaf node, it must
     be replaced with a leaf node (not merely one with an open left or
     right), to make sure that lefts and rights of descendents
     correspond properly to bit masks.  We use the rightmost descendent
     of x.  We could use any other leaf, but this is easy to locate and
     tends to counteract removal of leftmosts elsewhere, and so keeps
     paths shorter than minimally guaranteed.  This doesn't loop much
     because on average a node in a tree is near the bottom.
  3. If x is the base of a chain (i.e., has parent links) relink
     x's parent and children to x's replacement (or null if none).
*/
void unlink_large_chunk(struct malloc_state *state, struct malloc_tree_chunk *chunk) {
    struct malloc_tree_chunk *XP = chunk->parent;
    struct malloc_tree_chunk *R;
    if (chunk->bk != chunk) {
        struct malloc_tree_chunk *F = chunk->fd;
        R = chunk->bk;
        if (likely(ok_address(state, F) && F->bk == chunk && R->fd == chunk)) {
            F->bk = R;
            R->fd = F;
        }
        else {
            corruption_error(state);
        }
    }
    else {
        struct malloc_tree_chunk **RP;
        if (((R = *(RP = &(chunk->child[1]))) != 0) || ((R = *(RP = &(chunk->child[0]))) != 0)) {
            struct malloc_tree_chunk **CP;
            while ((*(CP = &(R->child[1])) != 0) || (*(CP = &(R->child[0])) != 0)) {
                R = *(RP = CP);
            }
            if (likely(ok_address(state, RP))) {
                *RP = 0;
            }
            else {
                corruption_error(state);
            }
        }
    }
    if (XP != 0) {
        struct malloc_tree_chunk **H = tree_bin_at(state, chunk->index);
        if (chunk == *H) {
            if ((*H = R) == 0) {
                clear_tree_map(state, chunk->index);
            }
        }
        else if (likely(ok_address(state, XP))) {
            if (XP->child[0] == chunk) {
                XP->child[0] = R;
            }
            else {
                XP->child[1] = R;
            }
        }
        else {
            corruption_error(state);
        }
        if (R != 0) {
            if (likely(ok_address(state, R))) {
                struct malloc_tree_chunk *C0, *C1;
                R->parent = XP;
                if ((C0 = chunk->child[0]) != 0) {
                    if (likely(ok_address(state, C0))) {
                        R->child[0] = C0;
                        C0->parent = R;
                    }
                    else {
                        corruption_error(state);
                    }
                }
                if ((C1 = chunk->child[1]) != 0) {
                    if (likely(ok_address(state, C1))) {
                        R->child[1] = C1;
                        C1->parent = R;
                    }
                    else {
                        corruption_error(state);
                    }
                }
            }
            else {
                corruption_error(state);
            }
        }
    }
}

/* Consolidate and bin a chunk. Differs from exported versions
   of free mainly in that the chunk need not be marked as inuse.
*/
void dispose_chunk(struct malloc_state *state, struct malloc_chunk *chunk, size_t size) {
    struct malloc_chunk *next = chunk_plus_offset(chunk, size);
    if (!prev_inuse(chunk)) {
        size_t prev_size = chunk->prev_foot;
        if (is_mmapped(chunk)) {
            size += prev_size + MMAP_FOOT_PAD;
            if (call_munmap((char *) chunk - prev_size, size) == 0) {
                state->footprint -= size;
            }
            return;
        }
        struct malloc_chunk *prev = chunk_minus_offset(chunk, prev_size);
        size += prev_size;
        chunk = prev;
        if (likely(ok_address(state, prev))) { /* consolidate backward */
            if (chunk != state->dv) {
                unlink_chunk(state, chunk, prev_size);
            }
            else if ((next->head & INUSE_BITS) == INUSE_BITS) {
                state->dv_size = size;
                set_free_with_prev_inuse(chunk, size, next);
                return;
            }
        }
        else {
            corruption_error(state);
            return;
        }
    }
    if (likely(ok_address(state, next))) {
        if (!curr_inuse(next)) {  /* consolidate forward */
            if (next == state->top) {
                size_t tsize = state->top_size += size;
                state->top = chunk;
                chunk->head = tsize | PREV_INUSE_BIT;
                if (chunk == state->dv) {
                    state->dv = 0;
                    state->dv_size = 0;
                }
                return;
            }
            else if (next == state->dv) {
                size_t dsize = state->dv_size += size;
                state->dv = chunk;
                set_size_and_prev_inuse_of_free_chunk(chunk, dsize);
                return;
            }
            else {
                size_t nsize = chunk_size(next);
                size += nsize;
                unlink_chunk(state, next, nsize);
                set_size_and_prev_inuse_of_free_chunk(chunk, size);
                if (chunk == state->dv) {
                    state->dv_size = size;
                    return;
                }
            }
        }
        else {
            set_free_with_prev_inuse(chunk, size, next);
        }
        insert_chunk(state, chunk, size);
    }
    else {
        corruption_error(state);
    }
}
