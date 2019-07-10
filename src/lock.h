#ifndef MALLOC_LOCK_H
#define MALLOC_LOCK_H

#include <sched.h>

#include "config.h"

/*
  When locks are defined, there is one global lock, plus
  one per-dl_heap_t lock.

  The global lock_ensures that params.magic and other unique
  params values are initialized only once. It also protects
  sequences of calls to MORECORE.  In many cases sys_alloc requires
  two calls, that should not be interleaved with calls by other
  threads.  This does not protect against direct calls to MORECORE
  by other threads not using this lock, so there is still code to
  cope the best we can on interference.

  Per-dl_heap_t locks surround calls to malloc, free, etc.
  By default, locks are simple non-reentrant mutexes.

  Because lock-protected regions generally have bounded times, it is
  OK to use the supplied simple spinlocks. Spinlocks are likely to
  improve performance for lightly contended applications, but worsen
  performance under heavy contention.

*/

#if USE_LOCKS || USE_SPIN_LOCKS || USE_RECURSIVE_LOCKS || USE_PTHREAD_LOCKS

/* First, define CAS_LOCK and CLEAR_LOCK on ints */
/* Note CAS_LOCK defined to return 0 on success */

#if defined(__GNUC__)
#define CAS_LOCK(sl)            __sync_lock_test_and_set(sl, 1)
#define CLEAR_LOCK(sl)          __sync_lock_release(sl)
#endif /* ... gcc spins locks ... */

/* How to yield for a spin lock */
#define SPINS_PER_YIELD         63
#define SPIN_LOCK_YIELD         sched_yield();
#define SPIN(C)                 { if ((++C & SPINS_PER_YIELD) == 0) { SPIN_LOCK_YIELD; } }

#if USE_RECURSIVE_LOCKS

#include "lock-recursive.h"

#elif USE_PTHREAD_LOCKS

#include "lock-pthread.h"

#else

#include "lock-spin.h"

#endif

extern MLOCK_T malloc_global_mutex;

#define ACQUIRE_MALLOC_GLOBAL_LOCK()  ACQUIRE_LOCK(&malloc_global_mutex);
#define RELEASE_MALLOC_GLOBAL_LOCK()  RELEASE_LOCK(&malloc_global_mutex);

/*
  PREACTION should be defined to return 0 on success, and nonzero on
  failure. If you are not using locking, you can redefine these to do
  anything you like.
*/
#define PREACTION(state)        ((use_lock(state)) ? ACQUIRE_LOCK(&(state)->mutex) : 0)
#define POSTACTION(state)       { if (use_lock(state)) { RELEASE_LOCK(&(state)->mutex); } }

#else /* USE_LOCKS */

#include "lock-nolock.h"

#define ACQUIRE_MALLOC_GLOBAL_LOCK()
#define RELEASE_MALLOC_GLOBAL_LOCK()

#define PREACTION(M)    (0)
#define POSTACTION(M)

#endif /* USE_LOCKS */

#if LOCK_AT_FORK

void pre_fork(void);

void post_fork_parent(void);

void post_fork_child(void);

#endif /* LOCK_AT_FORK */

#endif //MALLOC_LOCK_H
