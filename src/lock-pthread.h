#ifndef MALLOC_LOCK_PTHREAD_H
#define MALLOC_LOCK_PTHREAD_H

#include <pthread.h>

typedef pthread_mutex_t MLOCK_T;

#define ACQUIRE_LOCK(lock)      pthread_mutex_lock(lock)
#define RELEASE_LOCK(lock)      pthread_mutex_unlock(lock)
#define INITIAL_LOCK(lock)      pthread_init_lock(lock)
#define DESTROY_LOCK(lock)      pthread_mutex_destroy(lock)

int pthread_init_lock(MLOCK_T *lock);

#endif //MALLOC_LOCK_PTHREAD_H
