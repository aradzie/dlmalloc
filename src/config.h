#ifndef MALLOC_CONFIG_H
#define MALLOC_CONFIG_H

#include <sys/types.h>

#ifndef OVERRIDE
#define OVERRIDE 1
#endif /* OVERRIDE */

#ifndef EMULATE_SBRK
#define EMULATE_SBRK 1
#endif /* EMULATE_SBRK */

#ifndef USE_LOCKS
#define USE_LOCKS 1
#endif /* USE_LOCKS */

#ifndef LOCK_AT_FORK
#define LOCK_AT_FORK 0
#endif /* LOCK_AT_FORK */

#ifndef FOOTERS
#define FOOTERS 0
#endif  /* FOOTERS */

#ifndef INSECURE
#define INSECURE 0
#endif  /* INSECURE */

/* The maximum possible size_t value has all bits set */
#define MAX_SIZE_T (~(size_t) 0)
#define SIZE_T_BITSIZE (sizeof (size_t) << 3)

#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t) (2 * sizeof(void *)))
#endif  /* MALLOC_ALIGNMENT */

#ifndef MORECORE_CONTIGUOUS
#define MORECORE_CONTIGUOUS 1
#endif  /* MORECORE_CONTIGUOUS */

#ifndef DEFAULT_GRANULARITY
#if (MORECORE_CONTIGUOUS)
#define DEFAULT_GRANULARITY (0)  /* 0 means to compute in init_params */
#else   /* MORECORE_CONTIGUOUS */
#define DEFAULT_GRANULARITY ((size_t) 64U * (size_t) 1024U)
#endif  /* MORECORE_CONTIGUOUS */
#endif  /* DEFAULT_GRANULARITY */

#ifndef DEFAULT_TRIM_THRESHOLD
#define DEFAULT_TRIM_THRESHOLD ((size_t) 2U * (size_t) 1024U * (size_t) 1024U)
#endif  /* DEFAULT_TRIM_THRESHOLD */

#ifndef DEFAULT_MMAP_THRESHOLD
#define DEFAULT_MMAP_THRESHOLD ((size_t) 256U * (size_t) 1024U)
#endif  /* DEFAULT_MMAP_THRESHOLD */

#ifndef MAX_RELEASE_CHECK_RATE
#define MAX_RELEASE_CHECK_RATE 4095
#endif /* MAX_RELEASE_CHECK_RATE */

#define USE_MMAP_BIT            (1U)
/* Common code for all lock types */
#define USE_LOCK_BIT            (2U)
/* mstate bit set if contiguous morecore disabled or failed */
#define USE_NONCONTIGUOUS_BIT   (4U)
/* segment bit set in dl_create_heap_with_base */
#define EXTERN_BIT              (8U)

#if defined(__GNUC__) || defined(__clang__)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define dl_force_inline __inline __attribute__((always_inline))
#else
#define dl_force_inline inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#define dl_export __attribute__((visibility ("default")))
#else
#define dl_export
#endif

#if (defined(__GNUC__) || defined(__clang__)) && !defined(__MACH__)
#if (defined(__GNUC__) && __GNUC__ >= 9)
#define DL_FORWARD(fun) __attribute__((alias(#fun), used, visibility("default"), copy(fun)))
#else
#define DL_FORWARD(fun) __attribute__((alias(#fun), used, visibility("default")))
#endif
#define DL_FORWARD_1(fun, x)            DL_FORWARD(fun)
#define DL_FORWARD_2(fun, x, y)         DL_FORWARD(fun)
#define DL_FORWARD_3(fun, x, y, z)      DL_FORWARD(fun)
#define DL_FORWARD0_1(fun, x)           DL_FORWARD(fun)
#define DL_FORWARD0_2(fun, x, y)        DL_FORWARD(fun)
#define DL_FORWARD0_3(fun, x, y, z)     DL_FORWARD(fun)
#else
#define DL_FORWARD_1(fun, x)            { return fun(x); }
#define DL_FORWARD_2(fun, x, y)         { return fun(x, y); }
#define DL_FORWARD_3(fun, x, y, z)      { return fun(x, y, z); }
#define DL_FORWARD0_1(fun, x)           { fun(x); }
#define DL_FORWARD0_2(fun, x, y)        { fun(x, y); }
#define DL_FORWARD0_3(fun, x, y, z)     { fun(x, y, z); }
#endif

#endif //MALLOC_CONFIG_H
