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

Generated at: 2026-02-09T02:29:33Z
