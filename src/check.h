#ifndef MALLOC_CHECK_H
#define MALLOC_CHECK_H

/* ----------------------- Runtime Check Support ------------------------- */

/*
  For security, the main invariant is that malloc/free/etc never
  writes to a static address other than malloc_state, unless static
  malloc_state itself has been corrupted, which cannot occur via
  malloc (because of these checks). In essence this means that we
  believe all pointers, sizes, maps etc held in malloc_state, but
  check all of those linked or offsetted from other embedded data
  structures.  These checks are interspersed with main code in a way
  that tends to minimize their run-time cost.

  When FOOTERS is defined, in addition to range checking, we also
  verify footer fields of inuse chunks, which can be used guarantee
  that the mstate controlling malloc/free is intact.  This is a
  streamlined version of the approach described by William Robertson
  et al in "Run-time Detection of Heap-based Overflows" LISA'03
  http://www.usenix.org/events/lisa03/tech/robertson.html The footer
  of an inuse chunk holds the xor of its mstate and a random seed,
  that is checked upon calls to free() and realloc().  This is
  (probabalistically) unguessable from outside the program, but can be
  computed by any code successfully malloc'ing any chunk, so does not
  itself provide protection against code that has already broken
  security through some other means.  Unlike Robertson et al, we
  always dynamically check addresses of all offset chunks (previous,
  next, etc). This turns out to be cheaper than relying on hashes.
*/

#if !INSECURE

/* Check if address a is at least as high as any from MORECORE or MMAP */
#define ok_address(M, a)        ((char*) (a) >= (M)->least_addr)
/* Check if address of next chunk n is higher than base chunk p */
#define ok_next(p, n)           ((char*) (p) < (char*) (n))
/* Check if p has inuse status */
#define ok_inuse(p)             is_inuse(p)
/* Check if p has its prev_inuse bit on */
#define ok_prev_inuse(p)        prev_inuse(p)

#else /* !INSECURE */

#define ok_address(M, a)        (1)
#define ok_next(b, n)           (1)
#define ok_inuse(p)             (1)
#define ok_prev_inuse(p)        (1)

#endif /* !INSECURE */

#if (FOOTERS && !INSECURE)

/* Check if (alleged) mstate m has expected magic field */
#define ok_magic(M)             ((M)->magic == params.magic)

#else  /* (FOOTERS && !INSECURE) */

#define ok_magic(M)             (1)

#endif /* (FOOTERS && !INSECURE) */

#endif //MALLOC_CHECK_H
