#include "tlv.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define COV_BITMAP_BITS 65536u
#define COV_BITMAP_BYTES (COV_BITMAP_BITS / 8u)

static uint8_t g_cov_bitmap[COV_BITMAP_BYTES];
static uint32_t g_cov_unique = 0;
static uint32_t g_cov_hits = 0;

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

void tlv_cov_reset(void) {
    memset(g_cov_bitmap, 0, sizeof(g_cov_bitmap));
    g_cov_unique = 0;
    g_cov_hits = 0;
}

void tlv_cov_event(uint8_t type, uint8_t flags, int depth, uint16_t len, int valid_len) {
    uint32_t len_bucket = (uint32_t)(len >> 3) & 0x3FFu;
    uint32_t depth_bucket = (uint32_t)(depth & 0x0Fu);
    uint32_t key = ((uint32_t)type)
                 ^ (((uint32_t)flags) << 8)
                 ^ (depth_bucket << 16)
                 ^ (len_bucket << 20)
                 ^ ((valid_len ? 1u : 0u) << 31);
    uint32_t edge = mix32(key) & (COV_BITMAP_BITS - 1u);
    uint32_t idx = edge >> 3;
    uint8_t bit = (uint8_t)(1u << (edge & 7u));
    if ((g_cov_bitmap[idx] & bit) == 0) {
        g_cov_bitmap[idx] |= bit;
        g_cov_unique++;
    }
    g_cov_hits++;
}

uint32_t tlv_cov_unique_edges(void) {
    return g_cov_unique;
}

uint32_t tlv_cov_total_hits(void) {
    return g_cov_hits;
}

uint64_t tlv_cov_signature(void) {
    /* FNV-1a over bitmap + counters for stable, compact signature. */
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < COV_BITMAP_BYTES; i++) {
        h ^= (uint64_t)g_cov_bitmap[i];
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)g_cov_unique;
    h *= 1099511628211ULL;
    h ^= (uint64_t)g_cov_hits;
    h *= 1099511628211ULL;
    return h;
}

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
        tlv_cov_event(type, flags, c->depth, len, end <= c->size ? 1 : 0);
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
