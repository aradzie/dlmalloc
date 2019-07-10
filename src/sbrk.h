#ifndef DLALLOC_SBRK_H
#define DLALLOC_SBRK_H

#include <sys/types.h>

void *emulate_sbrk(ssize_t increment);

#endif //DLALLOC_SBRK_H
