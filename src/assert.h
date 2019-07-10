#ifndef MALLOC_ASSERT_H
#define MALLOC_ASSERT_H

#include <stdlib.h>

#ifdef DEBUG
#define dl_assert(x) if (!(x)) abort()
#else  /* DEBUG */
#ifndef dl_assert
#define dl_assert(x)
#endif
#endif /* DEBUG */

#endif //MALLOC_ASSERT_H
