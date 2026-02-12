#!/usr/bin/env python3
import argparse
from pathlib import Path
from datetime import datetime

DIRS = [
    "target/include",
    "target/src",
    "runner",
    "triage",
    "web",
    "web/templates",
    "web/static",
    "storage",
    "storage/runs",
    "tools",
    "corpus",
    "docs",
]

def file_map(generated_at: str) -> dict[str, str]:
    return {
        ".gitignore": """\
# Python
__pycache__/
*.pyc
.venv/
venv/
.mypy_cache/
.ruff_cache/
.pytest_cache/

# Builds
target/build/
*.o
*.a
*.so
*.out

# Runtime data
storage/runs/
!storage/runs/.keep

# OS/editor
.DS_Store
.vscode/
.idea/
""",
        "storage/runs/.keep": "",
        "requirements.txt": "flask>=3.0.0\n",
        "pyproject.toml": """\
[project]
name = "tlv-fuzz-triage"
version = "0.1.0"
requires-python = ">=3.10"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]
ignore = ["E501"]

[tool.black]
line-length = 100
target-version = ["py310"]

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = false
no_implicit_optional = true
check_untyped_defs = true
""",
        "README.md": f"""\
# TLV Fuzzing + Crash Triage (Ops Dashboard)

## Components
- `target/`: C TLV parser fuzz target (ASan/UBSan build)
- `runner/`: Python fuzz runner (file-based)
- `triage/`: Crash dedup / ASan parsing / minimization
- `web/`: Flask dashboard (workflow/ops oriented)
- `storage/`: Run/crash artifacts
- `corpus/`: Seed inputs
- `tools/`: Utility scripts

## Quick start (skeleton)

1. Create venv and install deps:
   - python3 -m venv .venv
   - source .venv/bin/activate
   - pip install -r requirements.txt

2. Initialize skeleton + seeds:
   - python3 tools/init_project.py
   - python3 tools/generate_seeds.py

3. Build and run target:
   - make -C target asan
   - ./target/build/tlv_target corpus/seed_08.bin

4. Run dashboard:
   - FLASK_APP=web.app flask run

Generated at: {generated_at}
""",
        "tools/README.md": """\
# tools/

- init_project.py: create directories and skeleton files
- generate_seeds.py: generate corpus seeds (TLV format)
- dump_seeds.py: decode/dump TLV seeds (supports nested TLV)
""",
        "docs/architecture.md": """\
# Architecture

Data flow:
corpus/ -> runner -> storage/runs/<run_id>/crashes/<crash_id>/ -> triage -> web

Notes:
- File-based inputs
- TLV parsing uses sliding recovery on truncation (off += 1)
- Nested TLV (type 0x03) supported up to max_depth
""",
        "runner/__init__.py": "",
        "triage/__init__.py": "",
        "web/__init__.py": "",
        "web/app.py": """\
from __future__ import annotations

from pathlib import Path
from flask import Flask, render_template

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["RUNS_DIR"] = Path("storage") / "runs"

    @app.get("/")
    def index():
        runs_dir: Path = app.config["RUNS_DIR"]
        runs = []
        if runs_dir.exists():
            for p in sorted(runs_dir.iterdir()):
                if p.is_dir():
                    runs.append(p.name)
        return render_template("index.html", runs=runs)

    return app

app = create_app()
""",
        "web/templates/index.html": """\
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>TLV Fuzz Triage</title>
  </head>
  <body>
    <h1>TLV Fuzz Triage</h1>
    <p>Runs directory: <code>storage/runs</code></p>
    <h2>Runs</h2>
    {% if runs %}
      <ul>
      {% for r in runs %}
        <li>{{ r }}</li>
      {% endfor %}
      </ul>
    {% else %}
      <p><em>No runs yet.</em></p>
    {% endif %}
  </body>
</html>
""",
        "target/Makefile": """\
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
\tmkdir -p $(OUTDIR)

debug: $(OUTDIR)
\t$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SRC) -o $(OUT)

asan: $(OUTDIR)
\t$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(CFLAGS_ASAN) $(SRC) $(LDFLAGS_ASAN) -o $(OUT)

clean:
\trm -rf $(OUTDIR)
""",
        "target/include/tlv.h": """\
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
""",
        "target/src/main.c": """\
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
        fprintf(stderr, "Usage: %s <input.bin>\n", argv[0]);
        return 2;
    }

    uint8_t *buf = NULL;
    size_t size = 0;
    if (read_file(argv[1], &buf, &size) != 0) {
        fprintf(stderr, "Failed to read file: %s\n", argv[1]);
        return 2;
    }

    Cursor c = {.buf = buf, .size = size, .off = 0, .depth = 0, .steps = 0};
    ParseLimits limits = {.max_depth = 4, .max_records = 10000, .max_steps = size ? (size * 10) : 10};

    int rc = tlv_parse_stream(&c, &limits);
    free(buf);
    return rc == 0 ? 0 : 1;
}
""",
        "target/src/tlv.c": """\
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
""",
        "target/src/handlers.c": """\
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
""",
    }

def write_file(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        print(f"Skip (exists): {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Wrote: {path}")

def main() -> None:
    ap = argparse.ArgumentParser(description="Initialize project skeleton (dirs + basic files).")
    ap.add_argument("--root", default=None, help="Project root directory (default: ../relative to script)")
    ap.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = ap.parse_args()

    if args.root is None:
        # tools/ 디렉토리의 부모를 기준으로 프로젝트 루트 설정
        script_dir = Path(__file__).parent
        root = script_dir.parent.resolve()
    else:
        root = Path(args.root).resolve()
    print(f"Init project at: {root}")

    for d in DIRS:
        p = root / d
        p.mkdir(parents=True, exist_ok=True)
        print(f"Dir: {p}")

    generated_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    fm = file_map(generated_at)
    for rel, content in fm.items():
        write_file(root / rel, content, force=args.force)

    print("\nDone.")

if __name__ == "__main__":
    main()
