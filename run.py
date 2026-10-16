"""Simple project entry point: sudo python3 run.py [build|health-check]."""

from pathlib import Path

from wgproxy.cli import main

if __name__ == "__main__":
    raise SystemExit(main(simple=True, project_root=Path(__file__).resolve().parent))
