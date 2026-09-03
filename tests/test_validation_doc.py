"""Keeps VALIDATION.md honest.

The value of that document is that every empirical finding names the test which
guards it. A renamed or deleted test would turn it into folklore silently, so
the references are checked here rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
DOC = TESTS_DIR / "VALIDATION.md"

REFERENCE = re.compile(r"(test_[a-z0-9_]+\.py)::(test_[a-z0-9_]+)")


def cited_references() -> list[tuple[str, str]]:
    return sorted(set(REFERENCE.findall(DOC.read_text(encoding="utf-8"))))


def test_doc_exists():
    assert DOC.exists(), "tests/VALIDATION.md is the validation record; do not delete it"


def test_doc_cites_tests_at_all():
    # A findings document with no test references has stopped being verifiable.
    assert len(cited_references()) >= 15


@pytest.mark.parametrize("filename,test_name", cited_references())
def test_every_cited_test_exists(filename: str, test_name: str):
    path = TESTS_DIR / filename
    assert path.exists(), f"VALIDATION.md cites {filename}, which does not exist"
    source = path.read_text(encoding="utf-8")
    assert re.search(rf"^def {re.escape(test_name)}\(", source, re.MULTILINE), (
        f"VALIDATION.md cites {filename}::{test_name}, which is not defined there. "
        "If the test was renamed, update the document so the finding stays traceable."
    )


def test_every_test_module_is_listed_in_the_inventory():
    doc = DOC.read_text(encoding="utf-8")
    modules = {p.name for p in TESTS_DIR.glob("test_*.py")} - {Path(__file__).name}
    missing = {m for m in modules if m not in doc}
    assert not missing, f"test modules absent from the VALIDATION.md inventory: {sorted(missing)}"
