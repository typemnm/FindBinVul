#make -C target asan
CC ?= clang

OUTDIR := build
OUT := $(OUTDIR)/tlv_target

SRC := src/main.c src/tlv.c src/handlers.c

CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wpedantic -Iinclude -fno-common
CFLAGS_DEBUG  := -O1 -g

# Sanitizers (good defaults for fuzzing/triage)
SANITIZERS ?= address,undefined
CFLAGS_ASAN  := -fsanitize=$(SANITIZERS) -fno-omit-frame-pointer
LDFLAGS_ASAN := -fsanitize=$(SANITIZERS)

# Optional: make sanitizer findings stop immediately (helps dedup)
# You can disable by: make asan SAN_RECOVER=1
SAN_RECOVER ?= 0
ifeq ($(SAN_RECOVER),0)
  CFLAGS_ASAN += -fno-sanitize-recover=all
endif

.PHONY: all clean asan debug fast

all: asan

$(OUTDIR):
	mkdir -p $(OUTDIR)

debug: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SRC) -o $(OUT)

asan: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(CFLAGS_ASAN) $(SRC) -o $(OUT) $(LDFLAGS_ASAN)

fast: $(OUTDIR)
	$(CC) $(CFLAGS_COMMON) -O2 $(SRC) -o $(OUTDIR)/tlv_fast

clean:
	rm -rf $(OUTDIR)