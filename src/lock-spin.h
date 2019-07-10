#ifndef MALLOC_LOCK_SPIN_H
#define MALLOC_LOCK_SPIN_H

typedef int MLOCK_T;

#define ACQUIRE_LOCK(lock)      (CAS_LOCK(lock) ? spin_acquire_lock(lock) : 0)
#define RELEASE_LOCK(lock)      (CLEAR_LOCK(lock))
#define INITIAL_LOCK(lock)      (*lock = 0)
#define DESTROY_LOCK(lock)      (0)

int spin_acquire_lock(int *lock);

#endif //MALLOC_LOCK_SPIN_H
