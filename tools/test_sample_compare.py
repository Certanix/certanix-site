"""The second sample on /verify: two releases compared (public-demo plan WP2, C.12 to C.22).

    python3 -m pytest tools/test_sample_compare.py

The caption's numbers are read from the delta report's signed fields, never typed: this
walks the caption against the file the page serves. The page's summary of a delta report
is built by verify/delta-summary.mjs from those same fields; it is run here on the served
file with node. The wording rule covers Certanix's own prose, not values from signed fields.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

_VERIFY = Path(__file__).resolve().parents[1] / "verify"
_PAGE = (_VERIFY / "index.html").read_text("utf-8")
_APP = (_VERIFY / "app.mjs").read_text("utf-8")
_P = "wp2-aloha-transfer-cube-v1-act-pergroup-s0-n40-k8"
_A = f"sample/{_P}-release-a-v3.evidence-pack.json"
_B = f"sample/{_P}-release-b-v3.evidence-pack.json"
_DELTA = "sample/arm-compare-release-a-v3-vs-release-b-v3.delta-report.json"
_FORBIDDEN = ("certified", "compliant", "approved", "passes", "safe")


def _load(rel: str) -> dict:
    return json.loads((_VERIFY / rel).read_text("utf-8"))


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inside = False
        self.depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "section" and ("id", "sample-compare") in attrs:
            self.inside = True
        if self.inside and tag == "section":
            self.depth += 1

    def handle_endtag(self, tag):
        if self.inside and tag == "section":
            self.depth -= 1
            self.inside = self.depth > 0

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)


def _section_text() -> str:
    parser = _Text()
    parser.feed(_PAGE)
    return " ".join(" ".join(parser.parts).split())


def test_every_linked_file_is_served_with_the_digest_the_page_states():
    for rel in (_A, _B, _DELTA):
        digest = hashlib.sha256((_VERIFY / rel).read_bytes()).hexdigest()
        assert f'href="{rel}"' in _PAGE
        assert digest in _PAGE, rel


def test_the_caption_numbers_are_the_signed_fields():
    delta = _load(_DELTA)
    text = _section_text()
    rate = delta["pass_rate"]
    failed = {rate["baseline_total"] - rate["baseline_passed"], rate["candidate_total"] - rate["candidate_passed"]}
    assert failed == {3} and rate["baseline_total"] == rate["candidate_total"] == 8
    assert "Each fails 3 of 8" in text
    assert len(delta["transitions"]) == 8 and "the same eight scenarios" in text
    changed = {t["scenario_id"].rsplit("-", 1)[1]: t["kind"] for t in delta["transitions"] if t["kind"] != "unchanged"}
    assert changed == {"c034": "fixed", "c020": "broken"}
    assert "c034 fixed, c020 broken" in text
    assert delta["counts"]["unchanged"] == 6 and "six unchanged" in text


def test_the_delta_names_the_served_packs_and_the_dates_trace():
    from_delta = _load(_DELTA)
    a, b = _load(_A), _load(_B)
    assert from_delta["baseline"]["pack_id"] == a["id"]
    assert from_delta["candidate"]["pack_id"] == b["id"]
    # July 2024 is in release B's signed derivation; March 2025 is release A's public
    # revision date (2025-03-06), recorded in certanix-beta docs/demo/arm-compare/CEREMONY.md.
    # "published" makes the caption read it as that date, not a signed field (C.28).
    assert "the current one, published March 2025" in _section_text()
    assert "published 2024-07-16" in b["provenance"]["policy"]["derivation"]
    assert a["provenance"]["policy"]["revision"].startswith("ba73b276")


def test_the_new_prose_uses_no_forbidden_word():
    words = set(re.findall(r"[a-z]+", _section_text().lower()))
    summary = (_VERIFY / "delta-summary.mjs").read_text("utf-8")
    labels = " ".join(re.findall(r'\["([^"]+)",', summary)).lower()
    for word in _FORBIDDEN:
        assert word not in words, word
        assert word not in labels.split(), word


def test_the_summary_module_loads_before_the_network_closes_and_only_after_exit_0():
    assert 'import { deltaSummaryRows } from "./delta-summary.mjs";' in _APP
    assert "if (verified) renderDeltaSummary();" in _APP


@pytest.mark.skipif(shutil.which("node") is None, reason="node not on PATH")
def test_the_summary_rows_on_the_served_delta():
    script = (
        "import { deltaSummaryRows } from './verify/delta-summary.mjs';\n"
        "import { readFileSync } from 'node:fs';\n"
        f"const doc = JSON.parse(readFileSync('verify/{_DELTA}', 'utf8'));\n"
        "console.log(JSON.stringify(deltaSummaryRows(doc)));\n"
        "console.log(JSON.stringify(deltaSummaryRows({ artifact_type: 'evidence-pack' })));\n"
    )
    out = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=_VERIFY.parent, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    rows = dict((label, value) for label, value in json.loads(out[0]))
    delta = _load(_DELTA)
    assert rows["Baseline pack, canonical SHA-256"] == delta["baseline"]["canonical_sha256"]
    assert rows["Candidate pack, canonical SHA-256"] == delta["candidate"]["canonical_sha256"]
    assert rows["Scenarios compared"] == "8"
    assert rows["Failed in the baseline"] == rows["Failed in the candidate"] == "3 of 8"
    assert rows["Verdicts changed"] == [
        "2",
        "aloha-transfer-cube-v1-s0-c020: passed to failed (broken)",
        "aloha-transfer-cube-v1-s0-c034: failed to passed (fixed)",
    ]
    assert rows["Scenarios added or removed"] == "none"
    assert json.loads(out[1]) is None
