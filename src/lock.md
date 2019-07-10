### -DUSE_LOCKS=1
### -DUSE_SPIN_LOCKS=1

```c
// Lock type
int lock;

// Aqcuire
(__sync_lock_test_and_set(&lock, 1) ? spin_acquire_lock(&lock) : 0);

// Release
__sync_lock_release(&lock);
```

### -DUSE_RECURSIVE_LOCKS=1

```c
// Lock type
struct malloc_recursive_lock lock;

// Aqcuire
recursive_acquire_lock(&lock);

// Release
recursive_release_lock(&lock);
```

### -DUSE_PTHREAD_LOCKS=1

```c
// Lock type
pthread_mutex_t lock;

// Aqcuire
pthread_mutex_lock(&lock);

// Release
pthread_mutex_unlock(&lock);
```
