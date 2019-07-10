#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#ifndef USE_STD_FPUTS
#define USE_STD_FPUTS 0
#endif /* USE_STD_FPUTS */

static void unbuffered_fputs(FILE *file, char *buf) {
    int fd = fileno(file);
    size_t len = strlen(buf);
    while (len > 0) {
        size_t w = write(fd, buf, len);
        if (w == (size_t) -1) {
            break;
        }
        buf += w;
        len -= w;
    }
}

void dl_printf(const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
#if USE_STD_FPUTS
    setvbuf(stdout, 0, _IONBF, 0); /* Disable buffering to avoid memory allocations. */
    fputs(buf, stdout);
#else
    unbuffered_fputs(stdout, buf);
#endif
}

void dl_fprintf(FILE *file, const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
#if USE_STD_FPUTS
    setvbuf(file, 0, _IONBF, 0); /* Disable buffering to avoid memory allocations. */
    fputs(buf, file);
#else
    unbuffered_fputs(file, buf);
#endif
}
