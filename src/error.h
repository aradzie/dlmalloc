#ifndef MALLOC_ERROR_H
#define MALLOC_ERROR_H

#include "config.h"

struct malloc_state;

void malloc_failure();

/*
  corruption_error is triggered upon detected bad addresses.
*/
void corruption_error(struct malloc_state *state);

/*
  usage_error is triggered on detected bad frees and
  reallocs. The argument p is an address that might have triggered the
  fault. It is ignored by the two predefined actions, but might be
  useful in custom actions that try to help diagnose errors.
*/
void usage_error(struct malloc_state *state, void *p);

#endif //MALLOC_ERROR_H
