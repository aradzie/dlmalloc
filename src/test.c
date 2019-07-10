#include <stdint.h>

#include "malloc.h"
#include "log.h"

void inspector(void *start, void *end, size_t used_bytes, void *callback_arg) {
    (void) callback_arg; // unused
    dl_printf(
            "start=0x%016lX end=0x%016lX size=%6lu used_bytes=%6lu\n",
            (uintptr_t) start, (uintptr_t) end, (end - start), used_bytes);
}

void test_dl() {
    void *p1 = dl_malloc(8);
    dl_printf("p1=0x%016lX\n", (uintptr_t) p1);
    void *p2 = dl_malloc(16);
    dl_printf("p2=0x%016lX\n", (uintptr_t) p2);
    void *p3 = dl_malloc(1024 * 1024);
    dl_printf("p3=0x%016lX\n", (uintptr_t) p3);

    dl_free(p1);

    dl_printf("\ninspect all\n");
    dl_malloc_inspect_all(&inspector, 0);
    dl_printf("------\n");

#ifdef DEBUG
    dl_printf("\nprint allocations\n");
    dl_print_allocations();
    dl_printf("------\n");
#endif

    void *x = dl_malloc(8);
    dl_printf("p1=0x%016lX\n", (uintptr_t) p1);
    dl_free(x);

    dl_free(p2);
    dl_free(p3);
}

int main() {
    test_dl();
    return 0;
}
