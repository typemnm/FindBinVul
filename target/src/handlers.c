#include "tlv.h"
#include <stddef.h>
#include <stdint.h>

static int has_magic_b00b(const uint8_t *p, size_t n) {
    if (n < 2) return 0;
    for (size_t i = 0; i + 1 < n; i++) {
        if (p[i] == 0xB0 && p[i + 1] == 0x0B) return 1;
    }
    return 0;
}

static void handle_type_01(const TlvRecord *r) { (void)r; }
static void handle_type_02(const TlvRecord *r) { (void)r; }

static void handle_type_10(const TlvRecord *r) {
    if (has_magic_b00b(r->value, r->len)) {
        /* sub-parse placeholder */
    }
}

void handle_record(const TlvRecord *r, Cursor *c, const ParseLimits *limits) {
    switch (r->type) {
    case 0x01:
        handle_type_01(r);
        break;
    case 0x02:
        handle_type_02(r);
        break;
    case 0x03: {
        if (c->depth + 1 > limits->max_depth) break;
        Cursor child = {.buf = r->value, .size = r->len, .off = 0, .depth = c->depth + 1, .steps = 0};
        tlv_parse_stream(&child, limits);
        break;
    }
    case 0x10:
        handle_type_10(r);
        break;
    default:
        break;
    }
}
