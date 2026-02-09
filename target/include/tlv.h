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

#endif
