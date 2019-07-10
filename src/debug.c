#include "assert.h"
#include "check.h"
#include "config.h"
#include "debug.h"
#include "init.h"
#include "os.h"
#include "segment.h"

#ifdef DEBUG

/* extract next chunk's prev_inuse bit */
static inline int next_prev_inuse(void *chunk) {
    return (next_chunk(chunk)->head) & PREV_INUSE_BIT;
}

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void check_any_chunk(struct malloc_state *state, struct malloc_chunk *chunk) {
    dl_assert((is_aligned(chunk_to_mem(chunk))) || (chunk->head == FENCEPOST_HEAD));
    dl_assert(ok_address(state, chunk));
}

/* Check properties of top chunk */
void check_top_chunk(struct malloc_state *state, struct malloc_chunk *chunk) {
    struct malloc_segment *sp = segment_holding(state, (char *) chunk);
    size_t sz = chunk->head & ~INUSE_BITS; /* third-lowest bit can be set! */
    dl_assert(sp != 0);
    dl_assert((is_aligned(chunk_to_mem(chunk))) || (chunk->head == FENCEPOST_HEAD));
    dl_assert(ok_address(state, chunk));
    dl_assert(sz == state->top_size);
    dl_assert(sz > 0);
    dl_assert(sz == ((sp->base + sp->size) - (char *) chunk) - TOP_FOOT_SIZE);
    dl_assert(prev_inuse(chunk));
    dl_assert(!prev_inuse(chunk_plus_offset(chunk, sz)));
}

/* Check properties of (inuse) mmapped chunks */
void check_mmapped_chunk(struct malloc_state *state, struct malloc_chunk *chunk) {
    size_t sz = chunk_size(chunk);
    size_t len = sz + (chunk->prev_foot) + MMAP_FOOT_PAD;
    dl_assert(is_mmapped(chunk));
    dl_assert(use_mmap(state));
    dl_assert((is_aligned(chunk_to_mem(chunk))) || (chunk->head == FENCEPOST_HEAD));
    dl_assert(ok_address(state, chunk));
    dl_assert(!is_small(sz));
    dl_assert((len & (params.page_size - (size_t) 1)) == 0);
    dl_assert(chunk_plus_offset(chunk, sz)->head == FENCEPOST_HEAD);
    dl_assert(chunk_plus_offset(chunk, sz + sizeof(size_t))->head == 0);
}

/* Check properties of inuse chunks */
void check_inuse_chunk(struct malloc_state *state, struct malloc_chunk *chunk) {
    check_any_chunk(state, chunk);
    dl_assert(is_inuse(chunk));
    dl_assert(next_prev_inuse((struct any_chunk *) chunk));
    /* If not prev_inuse and not mmapped, previous chunk has OK offset */
    dl_assert(is_mmapped(chunk) || prev_inuse(chunk) || next_chunk(prev_chunk(chunk)) == chunk);
    if (is_mmapped(chunk)) {
        check_mmapped_chunk(state, chunk);
    }
}

/* Check properties of malloced chunks at the point they are malloced */
void check_malloced_chunk(struct malloc_state *state, void *mem, size_t size) {
    if (mem != 0) {
        struct malloc_chunk *p = mem_to_chunk(mem);
        size_t sz = p->head & ~INUSE_BITS;
        check_inuse_chunk(state, p);
        dl_assert((sz & CHUNK_ALIGN_MASK) == 0);
        dl_assert(sz >= MIN_CHUNK_SIZE);
        dl_assert(sz >= size);
        /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
        dl_assert(is_mmapped(p) || sz < (size + MIN_CHUNK_SIZE));
    }
}

/* Check properties of free chunks */
void check_free_chunk(struct malloc_state *state, struct malloc_chunk *chunk) {
    size_t sz = chunk_size(chunk);
    struct malloc_chunk *next = chunk_plus_offset(chunk, sz);
    check_any_chunk(state, chunk);
    dl_assert(!is_inuse(chunk));
    dl_assert(!next_prev_inuse(chunk));
    dl_assert (!is_mmapped(chunk));
    if (chunk != state->dv && chunk != state->top) {
        if (sz >= MIN_CHUNK_SIZE) {
            dl_assert((sz & CHUNK_ALIGN_MASK) == 0);
            dl_assert(is_aligned(chunk_to_mem(chunk)));
            dl_assert(next->prev_foot == sz);
            dl_assert(prev_inuse(chunk));
            dl_assert (next == state->top || is_inuse(next));
            dl_assert(chunk->fd->bk == chunk);
            dl_assert(chunk->bk->fd == chunk);
        }
        else {
            dl_assert(sz == sizeof(size_t)); /* markers are always of size sizeof(size_t) */
        }
    }
}

/* Check a tree and its subtrees.  */
static void check_tree(struct malloc_state *state, struct malloc_tree_chunk *chunk) {
    struct malloc_tree_chunk *head = 0;
    struct malloc_tree_chunk *u = chunk;
    bin_index_t tindex = chunk->index;
    size_t tsize = chunk_size(chunk);
    bin_index_t idx;
    compute_tree_index(tsize, idx);
    dl_assert(tindex == idx);
    dl_assert(tsize >= MIN_LARGE_SIZE);
    dl_assert(tsize >= minsize_for_tree_index(idx));
    dl_assert((idx == NUM_TREE_BINS - 1) || (tsize < minsize_for_tree_index((idx + 1))));

    do {
        /* traverse through chain of same-sized nodes */
        check_any_chunk(state, ((struct malloc_chunk *) u));
        dl_assert(u->index == tindex);
        dl_assert(chunk_size(u) == tsize);
        dl_assert(!is_inuse(u));
        dl_assert(!next_prev_inuse(u));
        dl_assert(u->fd->bk == u);
        dl_assert(u->bk->fd == u);
        if (u->parent == 0) {
            dl_assert(u->child[0] == 0);
            dl_assert(u->child[1] == 0);
        }
        else {
            dl_assert(head == 0); /* only one node on chain has parent */
            head = u;
            dl_assert(u->parent != u);
            dl_assert (u->parent->child[0] == u
                       || u->parent->child[1] == u
                       || *((struct malloc_tree_chunk **) (u->parent)) == u);
            if (u->child[0] != 0) {
                dl_assert(u->child[0]->parent == u);
                dl_assert(u->child[0] != u);
                check_tree(state, u->child[0]);
            }
            if (u->child[1] != 0) {
                dl_assert(u->child[1]->parent == u);
                dl_assert(u->child[1] != u);
                check_tree(state, u->child[1]);
            }
            if (u->child[0] != 0 && u->child[1] != 0) {
                dl_assert(chunk_size(u->child[0]) < chunk_size(u->child[1]));
            }
        }
        u = u->fd;
    }
    while (u != chunk);
    dl_assert(head != 0);
}

/*  Check all the chunks in a tree_bin.  */
static void check_tree_bin(struct malloc_state *state, bin_index_t index) {
    struct malloc_tree_chunk **tb = tree_bin_at(state, index);
    struct malloc_tree_chunk *t = *tb;
    int empty = (state->tree_map & (1U << index)) == 0;
    if (t == 0) {
        dl_assert(empty);
    }
    if (!empty) {
        check_tree(state, t);
    }
}

/*  Check all the chunks in a small_bin.  */
static void check_small_bin(struct malloc_state *state, bin_index_t index) {
    struct malloc_chunk *b = small_bin_at(state, index);
    struct malloc_chunk *p = b->bk;
    unsigned int empty = (state->small_map & (1U << index)) == 0;
    if (p == b) {
        dl_assert(empty);
    }
    if (!empty) {
        for (; p != b; p = p->bk) {
            size_t size = chunk_size(p);
            /* each chunk claims to be free */
            check_free_chunk(state, p);
            /* chunk belongs in bin */
            dl_assert(small_index(size) == index);
            dl_assert(p->bk == b || chunk_size(p->bk) == chunk_size(p));
            /* chunk is followed by an inuse chunk */
            struct malloc_chunk *q = next_chunk(p);
            if (q->head != FENCEPOST_HEAD) {
                check_inuse_chunk(state, q);
            }
        }
    }
}

/* Find x in a bin. Used in other check functions. */
static int bin_find(struct malloc_state *state, struct malloc_chunk *chunk) {
    size_t size = chunk_size(chunk);
    if (is_small(size)) {
        bin_index_t sidx = small_index(size);
        struct malloc_chunk *b = small_bin_at(state, sidx);
        if (small_map_is_marked(state, sidx)) {
            struct malloc_chunk *p = b;
            do {
                if (p == chunk) {
                    return 1;
                }
            }
            while ((p = p->fd) != b);
        }
    }
    else {
        bin_index_t tidx;
        compute_tree_index(size, tidx);
        if (tree_map_is_marked(state, tidx)) {
            struct malloc_tree_chunk *t = *tree_bin_at(state, tidx);
            size_t sizebits = size << leftshift_for_tree_index(tidx);
            while (t != 0 && chunk_size(t) != size) {
                t = t->child[(sizebits >> (SIZE_T_BITSIZE - (size_t) 1)) & 1];
                sizebits <<= 1;
            }
            if (t != 0) {
                struct malloc_tree_chunk *u = t;
                do {
                    if (u == (struct malloc_tree_chunk *) chunk) {
                        return 1;
                    }
                }
                while ((u = u->fd) != t);
            }
        }
    }
    return 0;
}

/* Traverse each chunk and check it; return total */
static size_t traverse_and_check(struct malloc_state *state) {
    size_t sum = 0;
    if (is_initialized(state)) {
        struct malloc_segment *s = &state->segment;
        sum += state->top_size + TOP_FOOT_SIZE;
        while (s != 0) {
            struct malloc_chunk *q = align_as_chunk(s->base);
            struct malloc_chunk *lastq = 0;
            dl_assert(prev_inuse(q));
            while (segment_holds(s, q) && q != state->top && q->head != FENCEPOST_HEAD) {
                sum += chunk_size(q);
                if (is_inuse(q)) {
                    dl_assert(!bin_find(state, q));
                    check_inuse_chunk(state, q);
                }
                else {
                    dl_assert(q == state->dv || bin_find(state, q));
                    dl_assert(lastq == 0 || is_inuse(lastq)); /* Not 2 consecutive free */
                    check_free_chunk(state, q);
                }
                lastq = q;
                q = next_chunk(q);
            }
            s = s->next;
        }
    }
    return sum;
}

/* Check all properties of malloc_state. */
void check_malloc_state(struct malloc_state *state) {
    bin_index_t i;
    size_t total;
    /* check bins */
    for (i = 0; i < NUM_SMALL_BINS; ++i) {
        check_small_bin(state, i);
    }
    for (i = 0; i < NUM_TREE_BINS; ++i) {
        check_tree_bin(state, i);
    }

    if (state->dv_size != 0) { /* check dv chunk */
        check_any_chunk(state, state->dv);
        dl_assert(state->dv_size == chunk_size(state->dv));
        dl_assert(state->dv_size >= MIN_CHUNK_SIZE);
        dl_assert(bin_find(state, state->dv) == 0);
    }

    if (state->top != 0) {   /* check top chunk */
        check_top_chunk(state, state->top);
        /*dl_assert(state->top_size == chunk_size(state->top)); redundant */
        dl_assert(state->top_size > 0);
        dl_assert(bin_find(state, state->top) == 0);
    }

    total = traverse_and_check(state);
    dl_assert(total <= state->footprint);
    dl_assert(state->footprint <= state->max_footprint);
}

#endif
