#ifndef MALLOC_CHUNK_H
#define MALLOC_CHUNK_H

#include <sys/types.h>

#include "config.h"

#define CHUNK_ALIGN_MASK    (MALLOC_ALIGNMENT - ((size_t) 1))

/* True if address a has acceptable alignment. */
static inline int is_aligned(void *p) {
    return ((size_t) p & CHUNK_ALIGN_MASK) == 0;
}

/* The number of bytes to offset an address to align it. */
static inline size_t align_offset(void *p) {
    return ((size_t) p & CHUNK_ALIGN_MASK) == 0
           ? 0
           : (MALLOC_ALIGNMENT - ((size_t) p & CHUNK_ALIGN_MASK)) & CHUNK_ALIGN_MASK;
}

/*
  TOP_FOOT_SIZE is padding at the end of a segment, including space
  that may be needed to place segment records and fenceposts when new
  non-contiguous segments are added.
*/
#define TOP_FOOT_SIZE \
  (align_offset(chunk_to_mem(0)) + pad_request(sizeof(struct malloc_segment)) + MIN_CHUNK_SIZE)

struct any_chunk {
    /* The first four fields must be compatible with malloc_chunk */
    size_t prev_foot;
    size_t head;
};

/*
  The head field of a chunk is or'ed with PREV_INUSE_BIT when previous
  adjacent chunk in use, and or'ed with CURR_INUSE_BIT if this chunk is in
  use, unless mmapped, in which case both bits are cleared.
*/

#define PREV_INUSE_BIT          ((size_t) 1)
#define CURR_INUSE_BIT          ((size_t) 2)
#define INUSE_BITS              (PREV_INUSE_BIT | CURR_INUSE_BIT)
#define FLAG_BITS               (PREV_INUSE_BIT | CURR_INUSE_BIT)

/* Head value for fenceposts */
#define FENCEPOST_HEAD          (INUSE_BITS | sizeof(size_t))

static inline size_t chunk_size(void *chunk) {
    return ((struct any_chunk *) chunk)->head & ~FLAG_BITS;
}

static inline size_t get_foot(void *chunk, size_t size) {
    return ((struct any_chunk *) ((char *) chunk + size))->prev_foot;
}

static inline void set_foot(void *chunk, size_t size) {
    ((struct any_chunk *) ((char *) chunk + size))->prev_foot = size;
}

static inline int curr_inuse(void *chunk) {
    return ((struct any_chunk *) chunk)->head & CURR_INUSE_BIT;
}

static inline int prev_inuse(void *chunk) {
    return ((struct any_chunk *) chunk)->head & PREV_INUSE_BIT;
}

static inline int is_inuse(void *chunk) {
    return (((struct any_chunk *) chunk)->head & INUSE_BITS) != PREV_INUSE_BIT;
}

static inline int is_mmapped(void *chunk) {
    return (((struct any_chunk *) chunk)->head & INUSE_BITS) == 0;
}

static inline void clear_prev_inuse(void *chunk) {
    ((struct any_chunk *) chunk)->head &= ~PREV_INUSE_BIT;
}

/* Set size, prev_inuse bit, and foot */
static inline void set_size_and_prev_inuse_of_free_chunk(void *chunk, size_t size) {
    ((struct any_chunk *) chunk)->head = size | PREV_INUSE_BIT;
    set_foot(chunk, size);
}

/* Set size, prev_inuse bit, foot, and clear next prev_inuse */
static inline void set_free_with_prev_inuse(void *chunk, size_t size, void *n) {
    clear_prev_inuse(n);
    set_size_and_prev_inuse_of_free_chunk(chunk, size);
}

/* -----------------------  Chunk representations ------------------------ */

/*
  (The following includes lightly edited explanations by Colin Plumb.)

  The malloc_chunk declaration below is misleading (but accurate and
  necessary).  It declares a "view" into memory allowing access to
  necessary fields at known offsets from a given base.

  Chunks of memory are maintained using a `boundary tag' method as
  originally described by Knuth.  (See the paper by Paul Wilson
  ftp://ftp.cs.utexas.edu/pub/garbage/allocsrv.ps for a survey of such
  techniques.)  Sizes of free chunks are stored both in the front of
  each chunk and at the end.  This makes consolidating fragmented
  chunks into bigger chunks fast.  The head fields also hold bits
  representing whether chunks are free or in use.

  Here are some pictures to make it clearer.  They are "exploded" to
  show that the state of a chunk can be thought of as extending from
  the high 31 bits of the head field of its header through the
  prev_foot and PREV_INUSE_BIT bit of the following chunk header.

  A chunk that's in use looks like:

   chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Size of previous chunk (if P = 0)                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
         | Size of this chunk                                         1| +-+
   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               |
         +-                                                             -+
         |                                                               |
         +-                                                             -+
         |                                                               :
         +-      size - sizeof(size_t) available payload bytes          -+
         :                                                               |
 chunk-> +-                                                             -+
         |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |1|
       | Size of next chunk (may or may not be in use)               | +-+
 mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    And if it's free, it looks like this:

   chunk-> +-                                                             -+
           | User payload (must be in use, or we would have merged!)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
         | Size of this chunk                                         0| +-+
   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Next pointer                                                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Prev pointer                                                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               :
         +-      size - sizeof(struct chunk) unused bytes               -+
         :                                                               |
 chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Size of this chunk                                            |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |0|
       | Size of next chunk (must be in use, or we would have merged)| +-+
 mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               :
       +- User payload                                                -+
       :                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                     |0|
                                                                     +-+
  Note that since we always merge adjacent free chunks, the chunks
  adjacent to a free chunk must be in use.

  Given a pointer to a chunk (which can be derived trivially from the
  payload pointer) we can, in O(1) time, find out whether the adjacent
  chunks are free, and if so, unlink them from the lists that they
  are on and merge them with the current chunk.

  Chunks always begin on even word boundaries, so the mem portion
  (which is returned to the user) is also on an even word boundary, and
  thus at least double-word aligned.

  The P (PREV_INUSE_BIT) bit, stored in the unused low-order bit of the
  chunk size (which is always a multiple of two words), is an in-use
  bit for the *previous* chunk.  If that bit is *clear*, then the
  word before the current chunk size contains the previous chunk
  size, and can be used to find the front of the previous chunk.
  The very first chunk allocated always has this bit set, preventing
  access to non-existent (or non-owned) memory. If pinuse is set for
  any given chunk, then you CANNOT determine the size of the
  previous chunk, and might even get a memory addressing fault when
  trying to do so.

  The C (CURR_INUSE_BIT) bit, stored in the unused second-lowest bit of
  the chunk size redundantly records whether the current chunk is
  inuse (unless the chunk is mmapped). This redundancy enables usage
  checks within free and realloc, and reduces indirection when freeing
  and consolidating chunks.

  Each freshly allocated chunk must have both cinuse and pinuse set.
  That is, each allocated chunk borders either a previously allocated
  and still in-use chunk, or the base of its memory arena. This is
  ensured by making all allocations from the `lowest' part of any
  found chunk.  Further, no free chunk physically borders another one,
  so each free chunk is known to be preceded and followed by either
  inuse chunks or the ends of memory.

  Note that the `foot' of the current chunk is actually represented
  as the prev_foot of the NEXT chunk. This makes it easier to
  deal with alignments etc but can be very confusing when trying
  to extend or adapt this code.

  The exceptions to all this are

     1. The special chunk `top' is the top-most available chunk (i.e.,
        the one bordering the end of available memory). It is treated
        specially.  Top is never included in any bin, is used only if
        no other chunk is available, and is released back to the
        system if it is very large (see M_TRIM_THRESHOLD).  In effect,
        the top chunk is treated as larger (and thus less well
        fitting) than any other available chunk.  The top chunk
        doesn't update its trailing size field since there is no next
        contiguous chunk that would have to index off it. However,
        space is still allocated for it (TOP_FOOT_SIZE) to enable
        separation or merging when space is extended.

     3. Chunks allocated via mmap, have both curr_inuse and prev_inuse bits
        cleared in their head fields.  Because they are allocated
        one-by-one, each must carry its own prev_foot field, which is
        also used to hold the offset this chunk has within its mmapped
        region, which is needed to preserve alignment. Each mmapped
        chunk is trailed by the first two fields of a fake next-chunk
        for sake of usage checks.

*/

struct malloc_chunk {
    size_t prev_foot;  /* Size of previous chunk (if free).  */
    size_t head;       /* Size and inuse bits. */
    struct malloc_chunk *fd;         /* double links -- used only if free. */
    struct malloc_chunk *bk;
};

typedef unsigned int bin_index_t;      /* Described below */
typedef unsigned int bin_map_t;        /* Described below */
typedef unsigned int flag_t;           /* The type of various bit flag sets */

/* ------------------- Chunks sizes and alignments ----------------------- */

#define MALLOC_CHUNK_SIZE   (sizeof(struct malloc_chunk))

#if FOOTERS
#define CHUNK_OVERHEAD      (sizeof(size_t) * 2)
#else /* FOOTERS */
#define CHUNK_OVERHEAD      (sizeof(size_t))
#endif /* FOOTERS */

/* MMapped chunks need a second word of overhead ... */
#define MMAP_CHUNK_OVERHEAD (sizeof(size_t) * 2)
/* ... and additional padding for fake next-chunk at foot */
#define MMAP_FOOT_PAD       (sizeof(size_t) * 4)

/* The smallest size we can malloc is an aligned minimal chunk */
#define MIN_CHUNK_SIZE      ((MALLOC_CHUNK_SIZE + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK)

/* conversion from malloc headers to user pointers, and back */
static inline void *chunk_to_mem(void *p) {
    return (void *) ((char *) p + sizeof(size_t) * 2);
}

static inline struct malloc_chunk *mem_to_chunk(void *p) {
    return (struct malloc_chunk *) ((char *) p - sizeof(size_t) * 2);
}

/* chunk associated with aligned address p */
static inline struct malloc_chunk *align_as_chunk(void *p) {
    return (struct malloc_chunk *) (p + align_offset(chunk_to_mem(p)));
}

/* Bounds on request (not chunk) sizes. */
#define MAX_REQUEST         ((-MIN_CHUNK_SIZE) << 2)
#define MIN_REQUEST         (MIN_CHUNK_SIZE - CHUNK_OVERHEAD - (size_t) 1)

/* pad request bytes into a usable size */
static inline size_t pad_request(size_t req) {
    return (req + CHUNK_OVERHEAD + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK;
}

/* pad request, checking for minimum (but not maximum) */
static inline size_t request_to_size(size_t req) {
    return req < MIN_REQUEST ? MIN_CHUNK_SIZE : pad_request(req);
}

/* Treat space at ptr +/- offset as a chunk */
static inline struct malloc_chunk *chunk_plus_offset(void *chunk, size_t size) {
    return (struct malloc_chunk *) (((char *) chunk) + size);
}

static inline struct malloc_chunk *chunk_minus_offset(void *chunk, size_t size) {
    return (struct malloc_chunk *) (((char *) chunk) - size);
}

/* Ptr to next or previous physical malloc_chunk. */
static inline struct malloc_chunk *next_chunk(void *chunk) {
    return (struct malloc_chunk *) (((char *) chunk) + (((struct any_chunk *) chunk)->head & ~FLAG_BITS));
}

static inline struct malloc_chunk *prev_chunk(void *chunk) {
    return (struct malloc_chunk *) (((char *) chunk) - (((struct any_chunk *) chunk)->prev_foot));
}

/* Get the internal overhead associated with chunk p */
static inline size_t overhead_for(void *chunk) {
    return is_mmapped(chunk) ? MMAP_CHUNK_OVERHEAD : CHUNK_OVERHEAD;
}

/* Return true if malloced space is not necessarily cleared */
static inline int calloc_must_clear(void *chunk) {
    return !is_mmapped(chunk);
}

/* macros to set up inuse chunks with or without footers */

struct malloc_state;

#if !FOOTERS

static inline void mark_inuse_foot(struct malloc_state *state, void *chunk, size_t size) {
    (void) state; // unused
    (void) chunk; // unused
    (void) size; // unused
}

/* Macros for setting head/foot of non-mmapped chunks */

/* Set curr_inuse bit and prev_inuse bit of next chunk */
static inline void set_inuse(struct malloc_state *state, void *chunk, size_t size) {
    (void) state; // unused
    ((struct any_chunk *) chunk)->head = (((struct any_chunk *) chunk)->head & PREV_INUSE_BIT) | size | CURR_INUSE_BIT;
    ((struct malloc_chunk *) (((char *) chunk) + size))->head |= PREV_INUSE_BIT;
}

/* Set curr_inuse and prev_inuse of this chunk and prev_inuse of next chunk */
static inline void set_inuse_and_prev_inuse(struct malloc_state *state, void *chunk, size_t size) {
    (void) state; // unused
    ((struct any_chunk *) chunk)->head = size | PREV_INUSE_BIT | CURR_INUSE_BIT;
    ((struct malloc_chunk *) (((char *) chunk) + size))->head |= PREV_INUSE_BIT;
}

/* Set size, curr_inuse and prev_inuse bit of this chunk */
static inline void set_size_and_prev_inuse_of_inuse_chunk(struct malloc_state *state, void *chunk, size_t size) {
    (void) state; // unused
    ((struct any_chunk *) chunk)->head = size | PREV_INUSE_BIT | CURR_INUSE_BIT;
}

#else /* FOOTERS */

/* Set foot of inuse chunk to be xor of mstate and seed */
#define mark_inuse_foot(M, p, s)\
    (((struct malloc_chunk *)((char*)(p) + (s)))->prev_foot = ((size_t)(M) ^ params.magic))

#define get_state_for(p)\
    ((struct malloc_state *)(((struct malloc_chunk *)((char*)(p) +\
    (chunk_size(p))))->prev_foot ^ params.magic))

#define set_inuse(M, p, s)\
    ((p)->head = (((p)->head & PREV_INUSE_BIT) | s | CURR_INUSE_BIT),\
    (((struct malloc_chunk *)(((char*)(p)) + (s)))->head |= PREV_INUSE_BIT), \
    mark_inuse_foot(M,p,s))

#define set_inuse_and_prev_inuse(M, p, s)\
    ((p)->head = (s | PREV_INUSE_BIT | CURR_INUSE_BIT),\
    (((struct malloc_chunk *)(((char*)(p)) + (s)))->head |= PREV_INUSE_BIT),\
    mark_inuse_foot(M, p, s))

#define set_size_and_prev_inuse_of_inuse_chunk(M, p, s)\
    ((p)->head = (s | PREV_INUSE_BIT | CURR_INUSE_BIT),\
    mark_inuse_foot(M, p, s))

#endif /* !FOOTERS */

/* ---------------------- Overlaid data structures ----------------------- */

/*
  When chunks are not in use, they are treated as nodes of either
  lists or trees.

  "Small"  chunks are stored in circular doubly-linked lists, and look
  like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Larger chunks are kept in a form of bitwise digital trees (aka
  tries) keyed on chunksizes.  Because malloc_tree_chunks are only for
  free chunks greater than 256 bytes, their size doesn't impose any
  constraints on user chunk sizes.  Each node looks like:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk of same size        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk of same size       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to left child (child[0])                  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to right child (child[1])                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to parent                                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             bin index of this chunk                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space                                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Each tree holding treenodes is a tree of unique chunk sizes.  Chunks
  of the same size are arranged in a circularly-linked list, with only
  the oldest chunk (the next to be used, in our FIFO ordering)
  actually in the tree.  (Tree members are distinguished by a non-null
  parent pointer.)  If a chunk with the same size an an existing node
  is inserted, it is linked off the existing node using pointers that
  work in the same way as fd/bk pointers of small chunks.

  Each tree contains a power of 2 sized range of chunk sizes (the
  smallest is 0x100 <= x < 0x180), which is is divided in half at each
  tree level, with the chunks in the smaller half of the range (0x100
  <= x < 0x140 for the top nose) in the left subtree and the larger
  half (0x140 <= x < 0x180) in the right subtree.  This is, of course,
  done by inspecting individual bits.

  Using these rules, each node's left subtree contains all smaller
  sizes than its right subtree.  However, the node at the root of each
  subtree has no particular ordering relationship to either.  (The
  dividing line between the subtree sizes is based on trie relation.)
  If we remove the last chunk of a given size from the interior of the
  tree, we need to replace it with a leaf node.  The tree ordering
  rules permit a node to be replaced by any leaf below it.

  The smallest chunk in a tree (a common operation in a best-fit
  allocator) can be found by walking a path to the leftmost leaf in
  the tree.  Unlike a usual binary tree, where we follow left child
  pointers until we reach a null, here we follow the right child
  pointer any time the left one is null, until we reach a leaf with
  both child pointers null. The smallest chunk in the tree will be
  somewhere along that path.

  The worst case number of steps to add, find, or remove a node is
  bounded by the number of bits differentiating chunks within
  bins. Under current bin calculations, this ranges from 6 up to 21
  (for 32 bit sizes) or up to 53 (for 64 bit sizes). The typical case
  is of course much better.
*/

struct malloc_tree_chunk {
    /* The first four fields must be compatible with malloc_chunk */
    size_t prev_foot;
    size_t head;
    struct malloc_tree_chunk *fd;
    struct malloc_tree_chunk *bk;

    struct malloc_tree_chunk *child[2];
    struct malloc_tree_chunk *parent;
    bin_index_t index;
};

/* A little helper macro for trees */
static inline struct malloc_tree_chunk *leftmost_child(struct malloc_tree_chunk *t) {
    return t->child[0] != 0 ? t->child[0] : t->child[1];
}

#define compute_tree_index(S, I)\
{\
  unsigned int X = S >> TREE_BIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NUM_TREE_BINS-1;\
  else {\
    unsigned int K = (unsigned) sizeof(X)*__CHAR_BIT__ - 1 - (unsigned) __builtin_clz(X); \
    I =  (bin_index_t) ((K << 1) + ((S >> (K + (TREE_BIN_SHIFT-1)) & 1)));\
  }\
}

void insert_chunk(struct malloc_state *, struct malloc_chunk *, size_t);

void unlink_chunk(struct malloc_state *, struct malloc_chunk *, size_t);

void insert_small_chunk(struct malloc_state *, struct malloc_chunk *, size_t);

void unlink_small_chunk(struct malloc_state *, struct malloc_chunk *, size_t);

void unlink_first_small_chunk(struct malloc_state *, struct malloc_chunk *, struct malloc_chunk *, bin_index_t);

void replace_dv(struct malloc_state *, struct malloc_chunk *, size_t);

void insert_large_chunk(struct malloc_state *, struct malloc_tree_chunk *, size_t);

void unlink_large_chunk(struct malloc_state *, struct malloc_tree_chunk *);

void dispose_chunk(struct malloc_state *, struct malloc_chunk *, size_t);

#endif //MALLOC_CHUNK_H
