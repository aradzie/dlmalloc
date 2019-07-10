#ifndef MALLOC_LOCK_RECURSIVE_H
#define MALLOC_LOCK_RECURSIVE_H

#include <pthread.h>

struct malloc_recursive_lock {
    int sl;
    unsigned int c;
    pthread_t thread_id;
};

typedef struct malloc_recursive_lock MLOCK_T;

#define ACQUIRE_LOCK(lock)      recursive_acquire_lock(lock)
#define RELEASE_LOCK(lock)      recursive_release_lock(lock)
#define INITIAL_LOCK(lock)      ((lock)->thread_id = (pthread_t) 0, (lock)->sl = 0, (lock)->c = 0)
#define DESTROY_LOCK(lock)      (0)

int recursive_acquire_lock(MLOCK_T *lock);

void recursive_release_lock(MLOCK_T *lock);

#endif //MALLOC_LOCK_RECURSIVE_H
