"""Entry point of the Python conformance driver (bin/xdrcheck-driver runs it with `python -I`, which leaves the
script's directory off sys.path; the driver's own package is put back on it here, and nothing else)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xdrcheck_driver.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
