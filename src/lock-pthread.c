#include "config.h"
#include "lock.h"

MLOCK_T malloc_global_mutex = PTHREAD_MUTEX_INITIALIZER;

int pthread_init_lock(MLOCK_T *lock) {
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr)) {
        return 1;
    }
    if (pthread_mutex_init(lock, &attr)) {
        return 1;
    }
    if (pthread_mutexattr_destroy(&attr)) {
        return 1;
    }
    return 0;
}
