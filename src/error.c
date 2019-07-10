#include <stdlib.h>
#include <errno.h>

#include "error.h"

inline void malloc_failure() {
    errno = ENOMEM;
}

/*
  corruption_error is triggered upon detected bad addresses.
*/
inline void corruption_error(struct malloc_state *state) {
    (void) state; // unused
    abort();
}

/*
  usage_error is triggered on detected bad frees and
  reallocs. The argument p is an address that might have triggered the
  fault. It is ignored by the two predefined actions, but might be
  useful in custom actions that try to help diagnose errors.
*/
inline void usage_error(struct malloc_state *state, void *p) {
    (void) state; // unused
    (void) p; // unused
    abort();
}
