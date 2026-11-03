"""The verify page shows the verifier's capability-gate statement, and decides nothing itself.

    python3 -m pytest tools/test_verify_page_capability_gate.py

The wording comes from `certanix-verify --json`. The page must show that field as it
arrives and must not write the wording itself, or a page could say what the verifier did not.
"""

from __future__ import annotations

from pathlib import Path

_APP = (Path(__file__).resolve().parents[1] / "verify" / "app.mjs").read_text("utf-8")


def test_the_row_shows_the_field_the_verifier_wrote() -> None:
    assert 'add("Capability gate", parsed.capability_gate);' in _APP


def test_the_page_does_not_write_the_wording_itself() -> None:
    assert "no harness in signed content" not in _APP
