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
