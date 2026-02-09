#include "tlv.h"
#include <stddef.h>
#include <stdint.h>

static uint16_t read_u16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int has_bytes(const Cursor *c, size_t n) {
    return c->off + n <= c->size;
}

/* forward decl; implemented in handlers.c */
void handle_record(const TlvRecord *r, Cursor *c, const ParseLimits *limits);

int tlv_parse_stream(Cursor *c, const ParseLimits *limits) {
    int records = 0;

    while (has_bytes(c, 4) && records < limits->max_records) {
        c->steps++;
        if (c->steps > limits->max_steps) {
            return -1;
        }

        uint8_t type = c->buf[c->off];
        uint8_t flags = c->buf[c->off + 1];
        uint16_t len = read_u16le(c->buf + c->off + 2);

        size_t end = c->off + 4u + (size_t)len;
        if (end <= c->size) {
            TlvRecord r = {
                .type = type,
                .flags = flags,
                .len = len,
                .value = c->buf + c->off + 4
            };
            handle_record(&r, c, limits);

            c->off = end;
            records++;
        } else {
            /* Sliding recovery (A): move forward by 1 byte and try again */
            c->off += 1;
        }
    }
    return 0;
}
