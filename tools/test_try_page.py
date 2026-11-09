"""certanix.eu/try, the five-minute page (public-demo plan WP3).

    python3 -m pytest tools/test_try_page.py

The page is generated in certanix-beta (tools/try_page.py render) from lines captured with
the pinned verifier, and run as printed on twelve legs there (try-page.yml). Here: every
link resolves to a file this site serves, the requirements file pins the wheel the /verify
page runs, the front page links to the page, and Certanix's prose (outside the captured
blocks) uses none of the forbidden words.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urljoin

_SITE = Path(__file__).resolve().parents[1]
_PAGE = (_SITE / "try" / "index.html").read_text("utf-8")


def test_every_relative_link_resolves_to_a_served_file():
    for href in re.findall(r'href="([^"#:]+)(?:#[^"]*)?"', _PAGE):
        target = urljoin("https://certanix.eu/try/", href).removeprefix("https://certanix.eu/")
        path = _SITE / target
        if target.endswith("/") or target == "":
            path = path / "index.html"
        assert path.is_file(), href
        # Tracked, not merely present: an ignored file is on disk here and missing online.
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(path.relative_to(_SITE))],
                                 cwd=_SITE, capture_output=True, check=False)
        assert tracked.returncode == 0, f"{href} is not tracked by git, so it is not published"


def test_the_requirements_pin_the_wheel_the_verify_page_runs():
    first = next(x for x in (_SITE / "try" / "requirements.txt").read_text("utf-8").splitlines() if not x.startswith("#"))
    bundle = json.loads((_SITE / "verify" / "runtime" / "verifier" / "bundle.json").read_text("utf-8"))
    wheel = next(w for w in bundle["wheels"] if w["file"].startswith("certanix_verify-"))
    assert first == f"certanix-verify==0.17.0 --hash=sha256:{wheel['sha256']}"
    assert "https://certanix.eu/try/requirements.txt" in _PAGE


def test_the_front_page_links_here_in_one_click():
    assert '<a href="/try/">Try it in five minutes</a>' in (_SITE / "index.html").read_text("utf-8")


def test_the_prose_outside_the_captured_blocks_uses_no_forbidden_word():
    prose = re.sub(r"<pre>.*?</pre>", " ", _PAGE, flags=re.S)
    prose = re.sub(r"<dl.*?</dl>", " ", prose, flags=re.S)
    prose = re.sub(r"<[^>]+>", " ", prose).lower()
    # The closing sentence names "compliant" and "safe" to say verification shows neither
    # (Axel's wording, C.15): checked verbatim, then left out of the word rule.
    closing = "it says nothing about whether the system is fit for any purpose, compliant with any law, or safe."
    flat = " ".join(prose.split())
    assert closing in flat
    words = set(re.findall(r"[a-z]+", flat.replace(closing, " ")))
    for word in ("certified", "compliant", "approved", "passes", "safe"):
        assert word not in words, word
