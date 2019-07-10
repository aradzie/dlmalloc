#include "state.h"
#include "segment.h"

/* Return a segment holding the given address. */
struct malloc_segment *segment_holding(struct malloc_state *state, void *p) {
    struct malloc_segment *segment = &state->segment;
    for (;;) {
        if (segment_holds(segment, p)) {
            return segment;
        }
        if ((segment = segment->next) == 0) {
            return 0;
        }
    }
}

/* Return true if segment contains a segment link */
int has_segment_link(struct malloc_state *state, struct malloc_segment *segment) {
    struct malloc_segment *sp = &state->segment;
    for (;;) {
        if (segment->base <= (char *) sp && (char *) sp < segment->base + segment->size) {
            return 1;
        }
        if ((sp = sp->next) == 0) {
            return 0;
        }
    }
}
