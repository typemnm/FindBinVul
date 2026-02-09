#include "tlv.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define F_UNSAFE 0x80

static uint32_t read_u32le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void crash_tag(const char *tag) {
    ssize_t _r;
    _r = write(2, "CRASH TAG=", 10);
    _r = write(2, tag, strlen(tag));
    _r = write(2, "\n", 1);
    (void)_r;
}

/* =========================
 * Type 0x01 : String
 * ========================= */
static void handle_type_01(const TlvRecord *r) {
    char local[32];

    if (r->len < 4) return;
    if (memcmp(r->value, "CMD:", 4) != 0) return;

    const uint8_t *token = r->value + 4;
    size_t token_len = r->len - 4;

    if (!(r->flags & F_UNSAFE)) {
        snprintf(local, sizeof(local), "%.*s",
                 (int)token_len, token);
        return;
    }

    if ((r->flags & F_UNSAFE) &&
        r->len == 33 &&
        memcmp(token, "CRASH", 5) == 0) {

        crash_tag("T01_STACK_OVERFLOW");
        memcpy(local, token, token_len); /* stack OOB write */
    }
}

/* =========================
 * Type 0x02 : u32 array
 * ========================= */
static void handle_type_02(const TlvRecord *r) {
    if (r->len % 4 != 0) return;

    size_t count = r->len / 4;
    uint32_t sum = 0;

    for (size_t i = 0; i < count; i++) {
        sum += read_u32le(r->value + i * 4);
    }

    if ((r->flags & F_UNSAFE) &&
        count == 7 &&
        read_u32le(r->value) == 0x41414141) {

        crash_tag("T02_HEAP_OOB");

        uint32_t *tmp = malloc(count * sizeof(uint32_t));
        if (!tmp) return;

        for (size_t i = 0; i < count; i++) {
            tmp[i] = read_u32le(r->value + i * 4);
        }

        tmp[count] = 0xDEADBEEF; /* heap OOB */
        sum *= 0x100000000ULL;  /* integer overflow */

        free(tmp);
    }
}

/* =========================
 * Type 0x10 : Magic scan
 * ========================= */
static void handle_type_10(const TlvRecord *r) {
    for (size_t i = 0; i + 1 < r->len; i++) {
        if (r->value[i] == 0xB0 && r->value[i + 1] == 0x0B) {

            if (!(r->flags & F_UNSAFE)) return;

            if (i + 2 + 4 > r->len) {
                crash_tag("T10_MAGIC_OOB_READ");
                uint32_t x = read_u32le(r->value + i + 2);
                (void)x;
            }
        }
    }
}

/* =========================
 * Dispatcher
 * ========================= */
void handle_record(const TlvRecord *r, Cursor *c, const ParseLimits *limits) {
    (void)limits;

    switch (r->type) {
    case 0x01:
        handle_type_01(r);
        break;
    case 0x02:
        handle_type_02(r);
        break;
    case 0x03: {
        if (c->depth + 1 > limits->max_depth) break;

        Cursor child = {
            .buf = r->value,
            .size = r->len,
            .off = 0,
            .depth = c->depth + 1,
            .steps = 0
        };

        /* normal nested parsing */
        tlv_parse_stream(&child, limits);

        /* stress path */
        if ((r->flags & F_UNSAFE) && c->depth == 4) {
            crash_tag("T03_NESTED_STRESS");
            tlv_parse_stream(&child, limits);
        }
        break;
    }
    case 0x10:
        handle_type_10(r);
        break;
    default:
        break;
    }
}
