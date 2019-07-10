#include "config.h"
#include "lock.h"
#include "assert.h"

MLOCK_T malloc_global_mutex = 0;

/* Plain spin locks use single word (embedded in malloc_states) */
int spin_acquire_lock(int *sl) {
    int spins = 0;
    while (*(volatile int *) sl != 0 || CAS_LOCK(sl)) {
        SPIN(spins);
    }
    return 0;
}
