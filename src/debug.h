#ifndef MALLOC_DEBUG_H
#define MALLOC_DEBUG_H

#include "chunk.h"
#include "config.h"
#include "state.h"

#ifdef DEBUG

void check_top_chunk(struct malloc_state *, struct malloc_chunk *);

void check_mmapped_chunk(struct malloc_state *, struct malloc_chunk *);

void check_inuse_chunk(struct malloc_state *, struct malloc_chunk *);

void check_malloced_chunk(struct malloc_state *, void *, size_t);

void check_free_chunk(struct malloc_state *, struct malloc_chunk *);

void check_malloc_state(struct malloc_state *);

#else

#define check_top_chunk(M, P)
#define check_mmapped_chunk(M, P)
#define check_inuse_chunk(M, P)
#define check_malloced_chunk(M, P, N)
#define check_free_chunk(M, P)
#define check_malloc_state(M)

#endif

#endif //MALLOC_DEBUG_H
