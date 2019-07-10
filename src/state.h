#ifndef MALLOC_STATE_H
#define MALLOC_STATE_H

#include "config.h"
#include "chunk.h"
#include "segment.h"
#include "lock.h"

/*
   A malloc_state holds all of the bookkeeping for a space.
   The main fields are:

  Top
    The topmost chunk of the currently active segment. Its size is
    cached in top_size.  The actual size of topmost space is
    top_size+TOP_FOOT_SIZE, which includes space reserved for adding
    fenceposts and segment records if necessary when getting more
    space from the system.  The size at which to autotrim top is
    cached from params in trim_check, except that it is disabled if
    an autotrim fails.

  Designated victim (dv)
    This is the preferred chunk for servicing small requests that
    don't have exact fits.  It is normally the chunk split off most
    recently to service another small request.  Its size is cached in
    dv_size. The link fields of this chunk are not maintained since it
    is not kept in a bin.

  SmallBins
    An array of bin headers for free chunks.  These bins hold chunks
    with sizes less than MIN_LARGE_SIZE bytes. Each bin contains
    chunks of all the same size, spaced 8 bytes apart.  To simplify
    use in double-linked lists, each bin header acts as a malloc_chunk
    pointing to the real first node, if it exists (else pointing to
    itself).  This avoids special-casing for headers.  But to avoid
    waste, we allocate only the fd/bk pointers of bins, and then use
    repositioning tricks to treat these as the fields of a chunk.

  TreeBins
    Treebins are pointers to the roots of trees holding a range of
    sizes. There are 2 equally spaced tree_bins for each power of two
    from TREE_SHIFT to TREE_SHIFT+16. The last bin holds anything
    larger.

  Bin maps
    There is one bit map for small bins ("small_map") and one for
    tree_bins ("tree_map).  Each bin sets its bit when non-empty, and
    clears the bit when empty.  Bit operations are then used to avoid
    bin-by-bin searching -- nearly all "search" is done without ever
    looking at bins that won't be selected.  The bit maps
    conservatively use 32 bits per map word, even if on 64bit system.
    For a good description of some of the bit-based techniques used
    here, see Henry S. Warren Jr's book "Hacker's Delight" (and
    supplement at http://hackersdelight.org/). Many of these are
    intended to reduce the branchiness of paths through malloc etc, as
    well as to reduce the number of memory locations read or written.

  Segments
    A list of segments headed by an embedded malloc_segment record
    representing the initial space.

  Address check support
    The least_addr field is the least address ever obtained from
    MORECORE or MMAP. Attempted frees and reallocs of any address less
    than this are trapped (unless INSECURE is defined).

  Magic tag
    A cross-check field that should always hold same value as params.magic.

  Max allowed footprint
    The maximum allowed bytes to allocate from system (zero means no limit)

  Flags
    Bits recording whether to use MMAP, locks, or contiguous MORECORE

  Statistics
    Each space keeps track of current and maximum system memory
    obtained via MORECORE or MMAP.

  Trim support
    Fields holding the amount of unused topmost memory that should trigger
    trimming, and a counter to force periodic scanning to release unused
    non-topmost segments.

  Locking
    If USE_LOCKS is defined, the "mutex" lock is acquired and released
    around every public call using this dl_heap_t.

  Extension support
    A void* pointer and a size_t field that can be used to help implement
    extensions to this malloc.
*/

/* Bin types, widths and sizes */
#define NUM_SMALL_BINS    (32U)
#define NUM_TREE_BINS     (32U)
#define SMALL_BIN_SHIFT   (3U)
#define TREE_BIN_SHIFT    (8U)
#define MIN_LARGE_SIZE    ((size_t) 1 << TREE_BIN_SHIFT)
#define MAX_SMALL_SIZE    (MIN_LARGE_SIZE - (size_t) 1)
#define MAX_SMALL_REQUEST (MAX_SMALL_SIZE - CHUNK_ALIGN_MASK - CHUNK_OVERHEAD)

/* ---------------------------- Indexing Bins ---------------------------- */

static inline int is_small(size_t size) {
    return (size >> SMALL_BIN_SHIFT) < NUM_SMALL_BINS;
}

static inline bin_index_t small_index(size_t size) {
    return (bin_index_t) (size >> SMALL_BIN_SHIFT);
}

static inline size_t small_index_to_size(bin_index_t index) {
    return index << SMALL_BIN_SHIFT;
}

/* Shift placing maximum resolved bit in a tree_bin at i as sign bit */
static inline bin_index_t leftshift_for_tree_index(bin_index_t i) {
    return i == NUM_TREE_BINS - 1 ? 0 : SIZE_T_BITSIZE - (size_t) 1 - ((i >> 1) + TREE_BIN_SHIFT - 2);
}

/* The size of the smallest chunk held in bin with index i */
static inline bin_index_t minsize_for_tree_index(bin_index_t i) {
    return ((size_t) 1 << ((i >> 1) + TREE_BIN_SHIFT))
           | (((size_t) (i & (size_t) 1)) << ((i >> 1) + TREE_BIN_SHIFT - 1));
}

struct malloc_state {
    bin_map_t small_map;
    bin_map_t tree_map;
    size_t dv_size;
    size_t top_size;
    char *least_addr;
    struct malloc_chunk *dv; /* designated victim */
    struct malloc_chunk *top;
    size_t trim_check;
    size_t release_checks;
    size_t magic;
    struct malloc_chunk *small_bins[(NUM_SMALL_BINS + 1) * 2];
    struct malloc_tree_chunk *tree_bins[NUM_TREE_BINS];
    size_t footprint;
    size_t max_footprint;
    size_t footprint_limit; /* zero means no limit */
    flag_t flags;
#if USE_LOCKS
    MLOCK_T mutex; /* locate lock among fields that rarely change */
#endif /* USE_LOCKS */
    struct malloc_segment segment;
};

static inline int is_initialized(struct malloc_state *state) {
    return state->top != 0;
}

/* addressing by index. See above about small_bin repositioning */
static inline struct malloc_chunk *small_bin_at(struct malloc_state *state, bin_index_t index) {
    return (struct malloc_chunk *) (char *) &(state->small_bins[index << 1]);
}

static inline struct malloc_tree_chunk **tree_bin_at(struct malloc_state *state, bin_index_t index) {
    return &(state->tree_bins[index]);
}

/* bit corresponding to given index */
static inline bin_map_t index_to_bit(bin_map_t index) {
    return (bin_map_t) 1 << index;
}

/* Mark bit with given index */
static inline bin_map_t mark_small_map(struct malloc_state *state, bin_map_t index) {
    return state->small_map |= index_to_bit(index);
}

/* Clear bit with given index */
static inline bin_map_t clear_small_map(struct malloc_state *state, bin_map_t index) {
    return state->small_map &= ~index_to_bit(index);
}

static inline int small_map_is_marked(struct malloc_state *state, bin_index_t index) {
    return state->small_map & index_to_bit(index);
}

static inline bin_map_t mark_tree_map(struct malloc_state *state, bin_map_t index) {
    return state->tree_map |= index_to_bit(index);
}

static inline bin_map_t clear_tree_map(struct malloc_state *state, bin_map_t index) {
    return state->tree_map &= ~index_to_bit(index);
}

static inline int tree_map_is_marked(struct malloc_state *state, bin_map_t index) {
    return state->tree_map & index_to_bit(index);
}

static inline int use_mmap(struct malloc_state *state) {
    return state->flags & USE_MMAP_BIT;
}

static inline void enable_mmap(struct malloc_state *state) {
    state->flags |= USE_MMAP_BIT;
}

static inline void disable_mmap(struct malloc_state *state) {
    state->flags &= ~USE_MMAP_BIT;
}

static inline int use_lock(struct malloc_state *state) {
    return state->flags & USE_LOCK_BIT;
}

static inline void enable_lock(struct malloc_state *state) {
    state->flags |= USE_LOCK_BIT;
}

static inline void disable_lock(struct malloc_state *state) {
    state->flags &= ~USE_LOCK_BIT;
}

static inline void set_lock(struct malloc_state *state, int locked) {
    state->flags = locked ? (state->flags | USE_LOCK_BIT) : (state->flags & ~USE_LOCK_BIT);
}

static inline int use_noncontiguous(struct malloc_state *state) {
    return state->flags & USE_NONCONTIGUOUS_BIT;
}

static inline void disable_contiguous(struct malloc_state *state) {
    state->flags |= USE_NONCONTIGUOUS_BIT;
}

static inline int should_trim(struct malloc_state *state, size_t size) {
    return size > state->trim_check;
}

void init_top(struct malloc_state *state, struct malloc_chunk *chunk, size_t size);

void init_bins(struct malloc_state *state);

void *prepend_alloc(struct malloc_state *state, char *new_base, char *old_base, size_t nb);

void add_segment(struct malloc_state *state, char *tbase, size_t tsize, flag_t mmapped);

#endif //MALLOC_STATE_H
