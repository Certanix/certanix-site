"""No site file names a certanix-verify version that was never published to PyPI.

    python3 -m pytest tools/test_published_versions.py   # or: python3 tools/test_published_versions.py

The verifier is built from a private repository whose own version numbers (for example
0.20.0+internal) are not releases; 0.17.1 was tagged and never published. A version a
visitor cannot install is a statement about software that does not exist for them, so:

* every version written next to the verifier's name (``certanix-verify 0.17.2``,
  ``certanix-verify==0.17.2``, ``certanix_verify-0.17.2``) is in PUBLISHED;
* every other bare ``0.x.y`` in a site text file is in PUBLISHED too. The site's other
  version numbers (Pyodide 314.0.7, cryptography 48.0.1, asn1crypto 1.5.1, ...) do not
  start with 0, so a bare ``0.x.y`` is the verifier's. The vendored Pyodide runtime and the
  signed sample packs are not the site's words and are skipped for this rule (the samples
  record component versions such as 0.26.0); the named rule still reads them.

PUBLISHED was read from https://pypi.org/pypi/certanix-verify/json on 2026-11-20, as
declared. A new release is added here by hand when the site moves to it. With the network,
one check confirms each listed version is on PyPI; CERTANIX_OFFLINE=1 skips that check
and says so.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

import pytest

SITE = Path(__file__).resolve().parents[1]
# 0.22.0: added as a prepared change, true only AFTER PUBLICATION (verify-pack-context S.5
# step 7). This commit is pushed only once PyPI serves 0.22.0; before that the network check
# below fails, as it should.
PUBLISHED = frozenset({"0.14.0", "0.15.0", "0.16.0", "0.16.1", "0.17.0", "0.17.2", "0.22.0"})

NAMED = re.compile(r"certanix[-_ ]verify(?:==|[ -]|\s+v)?(\d+\.\d+\.\d+(?:\+\w+)?)(?![\w.]*\d)", re.I)
BARE = re.compile(r"(?<![\w.])(0\.\d+\.\d+(?:\+\w+)?)(?![\w.]*\d)")
BINARY = (".whl", ".wasm", ".zip", ".pub")
NOT_SITE_WORDS = ("verify/runtime/pyodide/", "verify/sample/")


def site_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=SITE, capture_output=True, check=True)
    return [p for p in listed.stdout.decode().split("\0") if p and not p.endswith(BINARY)]


def unpublished(name: str, text: str) -> list[str]:
    found = [f"{name}: certanix-verify {v}" for v in NAMED.findall(text) if v not in PUBLISHED]
    if not name.startswith(NOT_SITE_WORDS):
        found += [f"{name}: bare {v}" for v in BARE.findall(text) if v not in PUBLISHED]
    return found


def test_no_site_file_names_an_unpublished_verifier_version():
    found = []
    for name in site_files():
        try:
            text = (SITE / name).read_text("utf-8")
        except UnicodeDecodeError:
            continue
        found += unpublished(name, text)
    # File names count too: the wheel the page loads.
    found += [f"file name {n}" for n in site_files() for v in NAMED.findall(n) if v not in PUBLISHED]
    assert not found, "\n".join(found)


@pytest.mark.parametrize("text", [
    "The plain-language summary (certanix-verify 0.20.0): the verifier's sentences",
    "a wheel without the field (0.19.0 and earlier) shows nothing here",
    "certanix-verify 0.21.0",
    "certanix-verify==0.17.1",
    "certanix_verify-0.17.1-py3-none-any.whl",
    "version 0.20.0+internal",
])
def test_the_check_catches_what_it_is_for(text):
    """The negative control: the strings this test was written after are caught."""
    assert unpublished("verify/app.mjs", text)


@pytest.mark.parametrize("text", [
    "certanix-verify 0.17.2 and 0.17.0", "certanix-verify==0.17.2",
    "Pyodide 314.0.7, cryptography 48.0.1, asn1crypto 1.5.1, CPython 3.14.2",
    "Annex III, section 1.2.1", "--bind 127.0.0.1",
])
def test_the_check_passes_what_is_published_or_not_the_verifier(text):
    assert not unpublished("verify/index.html", text)


def test_every_listed_version_is_on_pypi():
    if os.environ.get("CERTANIX_OFFLINE") == "1":
        pytest.skip("CERTANIX_OFFLINE=1: the PyPI release list was not read")
    with urllib.request.urlopen("https://pypi.org/pypi/certanix-verify/json", timeout=30) as r:
        releases = {v for v, files in json.load(r)["releases"].items() if files}
    assert PUBLISHED <= releases, sorted(PUBLISHED - releases)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
