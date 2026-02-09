# Architecture

Data flow:
corpus/ -> runner -> storage/runs/<run_id>/crashes/<crash_id>/ -> triage -> web

Notes:
- File-based inputs
- TLV parsing uses sliding recovery on truncation (off += 1)
- Nested TLV (type 0x03) supported up to max_depth
