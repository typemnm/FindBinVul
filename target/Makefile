CC ?= clang

CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wpedantic -Iinclude -fno-common
CFLAGS_DEBUG  := -O1 -g
CFLAGS_ASAN   := -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS_ASAN  := -fsanitize=address,undefined

SRC := src/main.c src/tlv.c src/handlers.c
OUTDIR := build
OUT := $(OUTDIR)/tlv_target

.PHONY: all clean asan debug fast

all: debug

$(OUTDIR):
	mkdir -p $(OUTDIR)

debug: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SRC) -o $(OUT)

asan: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) \
	      $(CFLAGS_ASAN) $(SRC) $(LDFLAGS_ASAN) -o $(OUT)

fast: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) -O2 $(SRC) -o $(OUTDIR)/tlv_fast

clean:
	rm -rf $(OUTDIR)
