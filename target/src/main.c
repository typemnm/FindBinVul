#include "tlv.h"
#include <stdio.h>
#include <stdlib.h>

static int read_file(const char *path, uint8_t **out_buf, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return -1; }

    *out_buf = buf;
    *out_size = (size_t)sz;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input.bin>
", argv[0]);
        return 2;
    }

    uint8_t *buf = NULL;
    size_t size = 0;
    if (read_file(argv[1], &buf, &size) != 0) {
        fprintf(stderr, "Failed to read file: %s
", argv[1]);
        return 2;
    }

    Cursor c = {.buf = buf, .size = size, .off = 0, .depth = 0, .steps = 0};
    ParseLimits limits = {.max_depth = 4, .max_records = 10000, .max_steps = size ? (size * 10) : 10};

    int rc = tlv_parse_stream(&c, &limits);
    free(buf);
    return rc == 0 ? 0 : 1;
}
