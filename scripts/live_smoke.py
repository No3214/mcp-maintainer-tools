"""Call every tool against the real providers and check stable, public facts.

Automated tests stay offline. This script finds provider drift that mocks cannot:
the 0.1.5 Cargo-name and OSV not-found defects were found this way. It sends only
the fixed public identifiers below, needs no key, and prints no response bodies.

Exit 0: every check passed or a provider was only unavailable.
Exit 1: at least one check failed (contract or data drift), or --strict and a
provider was unavailable.
"""

import argparse
import os
import sys
import time

from mcp_maintainer_tools import server as s
from mcp_maintainer_tools.http import UpstreamError, UpstreamUnavailable

LOG4SHELL = "CVE-2021-44228"


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _osv_query():
    out = s.osv_query("lodash", "4.17.20", "npm")
    _expect(out["page_count"] >= 1, "lodash 4.17.20 has no OSV advisories")


def _osv_batch():
    out = s.osv_batch([{"name": "lodash", "version": "4.17.20"}])
    _expect(out["queried"] and len(out["results"]) == 1, "batch result count")
    _expect(out["results"][0]["page_count"] >= 1, "batch found no advisories")


def _osv_vuln_found():
    out = s.osv_vuln("GHSA-jfh8-c2jp-5v3q")
    _expect(out["found"] is True, "known GHSA not found")


def _osv_vuln_absent():
    try:
        out = s.osv_vuln("GHSA-0000-0000-0000")
    except UpstreamUnavailable:
        # OSV answered, but the tool could not tell absence from an outage.
        raise AssertionError("unknown GHSA reported as an outage, not absence") from None
    _expect(out["found"] is False, "unknown GHSA not reported as absent")


def _nvd():
    out = s.nvd_cve(LOG4SHELL)
    _expect(out["found"] is True, "Log4Shell not found in NVD")


def _kev():
    out = s.kev_check([LOG4SHELL])
    _expect(LOG4SHELL in out["hits"], "Log4Shell not in KEV catalog")


def _epss():
    out = s.epss([LOG4SHELL])
    _expect(out["page_count"] == 1, "EPSS returned no score for Log4Shell")


def _deps(name: str, system: str, canonical: str):
    def check():
        out = s.depsdev_package(name, system)
        _expect(out["package_key"]["name"] == canonical, f"{system} canonical name drifted")

    return check


CHECKS = [
    ("osv_query lodash@4.17.20", _osv_query),
    ("osv_batch lodash@4.17.20", _osv_batch),
    ("osv_vuln known GHSA", _osv_vuln_found),
    ("osv_vuln unknown GHSA", _osv_vuln_absent),
    ("nvd_cve Log4Shell", _nvd),
    ("kev_check Log4Shell", _kev),
    ("epss Log4Shell", _epss),
    ("depsdev npm @types/node", _deps("@types/node", "npm", "@types/node")),
    ("depsdev pypi Jinja2", _deps("Jinja2", "pypi", "jinja2")),
    ("depsdev cargo proc_macro2", _deps("proc_macro2", "cargo", "proc-macro2")),
    ("depsdev cargo Serde", _deps("Serde", "cargo", "serde")),
]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true", help="treat unavailable as failure")
    args = parser.parse_args(argv)
    rows = []
    for label, check in CHECKS:
        started = time.monotonic()
        try:
            check()
            status, detail = "PASS", ""
        except UpstreamUnavailable as exc:
            status, detail = "UNAVAILABLE", str(exc)
        except (
            AssertionError,
            KeyError,
            TypeError,
            UpstreamError,
            s.UpstreamDataError,
            ValueError,
        ) as exc:
            status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
        rows.append((label, status, round(time.monotonic() - started, 2), detail))
        print(f"{status:<11} {label} ({rows[-1][2]} s) {detail}", flush=True)

    failed = [r for r in rows if r[1] == "FAIL"]
    unavailable = [r for r in rows if r[1] == "UNAVAILABLE"]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("| Check | Status | Seconds | Detail |\n|---|---|---|---|\n")
            for label, status, seconds, detail in rows:
                handle.write(f"| {label} | {status} | {seconds} | {detail} |\n")
    print(
        f"live smoke: {len(rows) - len(failed) - len(unavailable)} pass, "
        f"{len(failed)} fail, {len(unavailable)} unavailable"
    )
    return 1 if failed or (args.strict and unavailable) else 0


if __name__ == "__main__":
    sys.exit(main())
