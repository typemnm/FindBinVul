#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *buf;
    size_t size;
    size_t off;
    int depth;
    size_t steps;
} Cursor;

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t len; /* little-endian in input */
    const uint8_t *value;
} TlvRecord;

typedef struct {
    int max_depth;
    int max_records;
    size_t max_steps;
} ParseLimits;

int tlv_parse_stream(Cursor *c, const ParseLimits *limits);

/* Lightweight in-target coverage hooks for fuzzer feedback. */
void tlv_cov_reset(void);
void tlv_cov_event(uint8_t type, uint8_t flags, int depth, uint16_t len, int valid_len);
uint32_t tlv_cov_unique_edges(void);
uint32_t tlv_cov_total_hits(void);
uint64_t tlv_cov_signature(void);

#endif
