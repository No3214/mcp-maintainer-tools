"""Record the tested environment without credentials or arbitrary environment values."""

import argparse
import hashlib
import json
import os
import platform
import sys
import sysconfig
from importlib.metadata import distributions
from pathlib import Path

import mcp_maintainer_tools


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-installed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    origin = Path(mcp_maintainer_tools.__file__).resolve()
    installed_roots = {Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")}
    if args.require_installed and (
        origin.is_relative_to(root / "src")
        or not any(origin.is_relative_to(path) for path in installed_roots)
    ):
        raise SystemExit(
            "Wheel verification must import the installed package outside the checkout."
        )
    receipt = {
        "python": sys.version,
        "platform": platform.platform(),
        "package_version": mcp_maintainer_tools.__version__,
        "package_origin": str(origin),
        "ci": {
            key: os.environ.get(key)
            for key in ("GITHUB_SHA", "GITHUB_REF", "RUNNER_OS", "ImageOS", "ImageVersion")
        },
        "distributions": sorted(
            ({"name": dist.metadata["Name"], "version": dist.version} for dist in distributions()),
            key=lambda item: (item["name"].lower(), item["version"]),
        ),
        "archives_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((root / "dist").glob("*"))
            if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
        },
    }
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
