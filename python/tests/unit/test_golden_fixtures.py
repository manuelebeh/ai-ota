"""Parses every committed `.otapkg` v1 golden fixture through the PyO3 binding and
asserts the result matches `<name>.expected.json` — the same contract the Rust parser is
checked against in `crates/ota-package/tests/golden.rs`, giving cross-language parity
transitively (see `crates/ota-package/tests/golden/v1/README.md`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_ota import packaging

GOLDEN_DIR = Path(__file__).resolve().parents[3] / "crates" / "ota-package" / "tests" / "golden" / "v1"
FIXTURES = ["minimal", "delta", "full"]


@pytest.mark.parametrize("name", FIXTURES)
def test_golden_fixture_matches_expected_json(name: str) -> None:
    otapkg_path = GOLDEN_DIR / f"{name}.otapkg"
    expected_path = GOLDEN_DIR / f"{name}.expected.json"

    actual = packaging.inspect(str(otapkg_path))
    expected = json.loads(expected_path.read_text())

    assert actual == expected, f"{name}: Python parse does not match {expected_path}"


@pytest.mark.parametrize("name", FIXTURES)
def test_golden_fixture_under_size_cap(name: str) -> None:
    otapkg_path = GOLDEN_DIR / f"{name}.otapkg"
    assert otapkg_path.stat().st_size < 4096
