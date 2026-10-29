"""Source-checkout forwarding entrypoint; canonical implementation is packaged."""
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

# Source-checkout execution must add src before importing the packaged entrypoint.
from gateway.cli.evaluation import EvalCommandServices as EvalCommandServices, main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
