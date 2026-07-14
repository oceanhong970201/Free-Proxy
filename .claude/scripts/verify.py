#!/usr/bin/env python3
"""Thin wrapper so hooks/skills can call the verifier by a fixed path.

Delegates to `src/aggregator/cli.py verify` (Stage 1 CLI contract).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR", Path(__file__).resolve().parents[2]))


def main() -> int:
    cli = ROOT / "src" / "aggregator" / "cli.py"
    if not cli.exists():
        print(f"[verify.py] cli.py not found at {cli}", file=sys.stderr)
        return 2

    # Prefer running as a subprocess so typer/argparse behave identically.
    import subprocess

    args = [sys.executable, str(cli), "verify", *sys.argv[1:]]
    proc = subprocess.run(args, cwd=str(ROOT))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
