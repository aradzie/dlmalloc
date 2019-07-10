#ifndef DLALLOC_LOG_H
#define DLALLOC_LOG_H

#include <stdio.h>

// Our own limited `printf` that avoids memory allocation.
// We do this using `snprintf` with a limited buffer.

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
void dl_printf(const char *fmt, ...);

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
void dl_fprintf(FILE *file, const char *fmt, ...);

#endif //DLALLOC_LOG_H
