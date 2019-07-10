#include <pthread.h>

#include "config.h"
#include "lock.h"
#include "assert.h"

MLOCK_T malloc_global_mutex = {
        .sl = 0,
        .c = 0,
        .thread_id = (pthread_t) 0,
};

dl_force_inline int recursive_acquire_lock(MLOCK_T *lock) {
    pthread_t my_thread_id = pthread_self();
    int spins = 0;
    for (;;) {
        if (*((volatile int *) &lock->sl) == 0) {
            if (!CAS_LOCK(&lock->sl)) {
                lock->thread_id = my_thread_id;
                lock->c = 1;
                return 0;
            }
        }
        else if (pthread_equal(lock->thread_id, my_thread_id)) {
            ++lock->c;
            return 0;
        }
        SPIN(spins);
    }
}

dl_force_inline void recursive_release_lock(MLOCK_T *lock) {
    dl_assert(lock->sl != 0);
    if (--lock->c == 0) {
        CLEAR_LOCK(&lock->sl);
    }
}

