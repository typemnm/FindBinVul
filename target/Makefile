CC ?= clang
CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wpedantic -Iinclude
CFLAGS_DEBUG  := -O0 -g
CFLAGS_ASAN   := -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS_ASAN  := -fsanitize=address,undefined

SRC := src/main.c src/tlv.c src/handlers.c
OUTDIR := build
OUT := $(OUTDIR)/tlv_target

.PHONY: all clean asan debug

all: debug

$(OUTDIR):
	mkdir -p $(OUTDIR)

debug: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SRC) -o $(OUT)

asan: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(CFLAGS_ASAN) $(SRC) $(LDFLAGS_ASAN) -o $(OUT)

clean:
	rm -rf $(OUTDIR)
