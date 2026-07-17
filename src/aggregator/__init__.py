"""Free-Proxy aggregator package.

Local commands consistently load the repository ``.env`` file. CI-provided
environment variables keep precedence, so secrets injected by the runner are
never overwritten by a local file.
"""

from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
except ImportError:
    # Keep imports usable for tooling before dependencies are installed.
    pass
