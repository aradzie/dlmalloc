#include "config.h"
#include "lock.h"
#include "init.h"

#if USE_LOCKS || USE_SPIN_LOCKS || USE_RECURSIVE_LOCKS || USE_PTHREAD_LOCKS

#if USE_RECURSIVE_LOCKS

#include "lock-recursive.c"

#elif USE_PTHREAD_LOCKS

#include "lock-pthread.c"

#else

#include "lock-spin.c"

#endif

#endif /* USE_LOCKS */

#if LOCK_AT_FORK

void pre_fork(void) {
    ACQUIRE_LOCK(&global_malloc_state.mutex);
}

void post_fork_parent(void) {
    RELEASE_LOCK(&global_malloc_state.mutex);
}

void post_fork_child(void) {
    INITIAL_LOCK(&global_malloc_state.mutex);
}

#endif /* LOCK_AT_FORK */
