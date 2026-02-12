from __future__ import annotations

import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
import io
from datetime import datetime

from triage.repro import create_crash_summary


def create_app(runs_dir: str = "storage/runs", target_path: str = None) -> Flask:
    """Create and configure Flask app."""
    app = Flask(__name__)
    app.config["RUNS_DIR"] = Path(runs_dir)
    app.config["TARGET_PATH"] = target_path or "target/build/tlv_target"

    @app.get("/")
    def index():
        """Landing page with run list."""
        runs_dir = app.config["RUNS_DIR"]
        runs = []
        
        if runs_dir.exists():
            for p in sorted(runs_dir.iterdir(), reverse=True):
                if p.is_dir() and (p / "run.json").exists():
                    try:
                        run_meta = json.loads((p / "run.json").read_text())
                        crash_count = len(list((p / "crashes").glob("*"))) if (p / "crashes").exists() else 0
                        runs.append({
                            "run_id": p.name,
                            "created_at": run_meta.get("created_at"),
                            "iterations": run_meta.get("iterations"),
                            "crash_count": crash_count,
                        })
                    except Exception:
                        pass
        
        return render_template("runs.html", runs=runs)

    @app.get("/run/<run_id>")
    def view_run(run_id: str):
        """View crashes in a specific run."""
        run_dir = app.config["RUNS_DIR"] / run_id
        if not run_dir.exists():
            return {"error": "Run not found"}, 404
        
        crashes = []
        crashes_dir = run_dir / "crashes"
        
        if crashes_dir.exists():
            for crash_dir in sorted(crashes_dir.iterdir()):
                if crash_dir.is_dir() and (crash_dir / "meta.json").exists():
                    try:
                        summary = create_crash_summary(crash_dir, app.config["TARGET_PATH"])
                        crashes.append(summary)
                    except Exception:
                        pass
        
        # Sort by crash_id descending
        crashes.sort(key=lambda x: x.get("crash_id", ""), reverse=True)
        
        return render_template("run_detail.html", run_id=run_id, crashes=crashes)

    @app.get("/crash/<run_id>/<crash_id>")
    def view_crash(run_id: str, crash_id: str):
        """View detailed info about a specific crash."""
        crash_dir = app.config["RUNS_DIR"] / run_id / "crashes" / crash_id
        if not crash_dir.exists():
            return {"error": "Crash not found"}, 404
        
        meta_path = crash_dir / "meta.json"
        if not meta_path.exists():
            return {"error": "Crash metadata not found"}, 404
        
        meta = json.loads(meta_path.read_text())
        stderr_text = ""
        stdout_text = ""
        
        stderr_file = crash_dir / "stderr.txt"
        if stderr_file.exists():
            stderr_text = stderr_file.read_text(encoding="utf-8", errors="replace")
        
        stdout_file = crash_dir / "stdout.txt"
        if stdout_file.exists():
            stdout_text = stdout_file.read_text(encoding="utf-8", errors="replace")
        
        summary = create_crash_summary(crash_dir, app.config["TARGET_PATH"])
        
        # Read repro script content
        repro_script_path = crash_dir / "repro.sh"
        repro_script_content = ""
        if repro_script_path.exists():
            repro_script_content = repro_script_path.read_text()
        
        # Check if minimized input exists
        has_minimized = (crash_dir / "minimized.bin").exists()
        
        return render_template(
            "crash_detail.html",
            run_id=run_id,
            crash_id=crash_id,
            summary=summary,
            meta=meta,
            stderr_text=stderr_text,
            stdout_text=stdout_text,
            repro_script_content=repro_script_content,
            has_minimized=has_minimized,
        )

    @app.get("/api/crashes")
    def api_crashes():
        """API endpoint: list all crashes across runs."""
        runs_dir = app.config["RUNS_DIR"]
        crashes = []
        
        if runs_dir.exists():
            for run_dir in sorted(runs_dir.iterdir(), reverse=True):
                crashes_subdir = run_dir / "crashes"
                if not crashes_subdir.exists():
                    continue
                
                for crash_dir in sorted(crashes_subdir.iterdir()):
                    if not crash_dir.is_dir():
                        continue
                    
                    meta_path = crash_dir / "meta.json"
                    if not meta_path.exists():
                        continue
                    
                    try:
                        meta = json.loads(meta_path.read_text())
                        crashes.append({
                            "run_id": run_dir.name,
                            "crash_id": meta.get("crash_id"),
                            "created_at": meta.get("created_at"),
                            "crash_tag": meta.get("triage", {}).get("crash_tag"),
                            "asan_bug_type": meta.get("triage", {}).get("asan_bug_type"),
                        })
                    except Exception:
                        pass
        
        return {"crashes": crashes}

    @app.get("/download/<run_id>/<crash_id>/input.bin")
    def download_input(run_id: str, crash_id: str):
        """Download crash input file."""
        input_path = app.config["RUNS_DIR"] / run_id / "crashes" / crash_id / "input.bin"
        if not input_path.exists():
            return {"error": "File not found"}, 404
        
        return send_file(input_path, as_attachment=True, download_name=f"{crash_id}_input.bin")

    @app.get("/download/<run_id>/<crash_id>/minimized.bin")
    def download_minimized(run_id: str, crash_id: str):
        """Download minimized crash input file."""
        input_path = app.config["RUNS_DIR"] / run_id / "crashes" / crash_id / "minimized.bin"
        if not input_path.exists():
            return {"error": "File not found"}, 404
        
        return send_file(input_path, as_attachment=True, download_name=f"{crash_id}_minimized.bin")

    return app


# Default app instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
