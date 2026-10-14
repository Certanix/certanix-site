"""The licence pages show exactly the licence files of the certanix-verify package on PyPI.

    python3 -m pytest tools/test_licence_pages.py      # or: python3 tools/test_licence_pages.py

* The wheel the site carries is the one PyPI publishes (its sha256, from PyPI's JSON API).
  This needs the network; CERTANIX_OFFLINE=1 skips that one check, and says so.
* Each page's text, unescaped, is byte for byte the file in that wheel, and the page's
  <pre> is that file HTML-escaped and nothing else.
* LICENSE, NOTICE and PATENTS-NOTICE.md beside the pages are the wheel's files, and
  PATENTS-NOTICE.txt is PATENTS-NOTICE.md byte for byte.
* The committed files are what tools/licence_pages.py writes now.
* /verify/ links to the pages, and to the plain-text copy by its agreed text.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import licence_pages as lp  # noqa: E402

import pytest  # noqa: E402


def test_wheel_is_the_one_on_pypi():
    path, digest, version = lp.wheel()
    if os.environ.get("CERTANIX_OFFLINE") == "1":
        pytest.skip("CERTANIX_OFFLINE=1: the PyPI hash was not checked")
    url = f"https://pypi.org/pypi/certanix-verify/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        release = json.load(r)
    [published] = [u for u in release["urls"] if u["filename"] == path.name]
    assert published["digests"]["sha256"] == digest


@pytest.mark.parametrize("name,html_name", [(n, h) for n, h, *_ in lp.PAGES])
def test_page_text_is_the_wheel_file(name, html_name):
    wheel_bytes = lp.members(lp.wheel()[0])[name]
    page = (lp.LICENCE / html_name).read_text(encoding="utf-8")
    assert lp.pre_text(page).encode("utf-8") == wheel_bytes
    # Escaping is the only difference: the raw <pre> content is the escaped file.
    m = re.search(re.escape(lp.PRE_OPEN) + r"(.*?)" + re.escape(lp.PRE_CLOSE), page, re.S)
    assert m.group(1) == html.escape(wheel_bytes.decode("utf-8"), quote=False)
    assert page.count(lp.PRE_OPEN) == 1


def test_raw_files_are_the_wheel_files():
    files = lp.members(lp.wheel()[0])
    for name, data in files.items():
        assert (lp.LICENCE / name).read_bytes() == data, name
    for copy, source in lp.COPIES:
        assert (lp.LICENCE / copy).read_bytes() == files[source], copy


def test_committed_files_are_generated():
    for name, data in lp.render().items():
        assert (lp.LICENCE / name).read_bytes() == data, f"{name}: run tools/licence_pages.py"


def test_verify_page_links():
    page = (lp.VERIFY / "index.html").read_text(encoding="utf-8")
    hrefs = re.findall(r'href="(licence/[^"]+)"', page)
    assert set(hrefs) == {"licence/licence.html", "licence/notice.html",
                          "licence/patents.html", "licence/PATENTS-NOTICE.txt"}
    for href in hrefs:
        assert (lp.VERIFY / href).is_file(), href
    assert '<a href="licence/PATENTS-NOTICE.txt">PATENTS-NOTICE (plain text)</a>' in page


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
