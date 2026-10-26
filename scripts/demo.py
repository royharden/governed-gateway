"""Source-checkout forwarding entrypoint; canonical implementation is packaged."""
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

# A source checkout needs src on sys.path before importing these compatibility exports.
from gateway.cli.demo import (  # noqa: E402
    DemoPolicyEvidence as DemoPolicyEvidence,
    DemoServices as DemoServices,
    controller_request as controller_request,
    main as main,
    run_demo as run_demo,
)

if __name__ == "__main__":
    raise SystemExit(main())
