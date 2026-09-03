import json
from pathlib import Path

from javalogai.cli import main

FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "payment-service.log")


def test_report_runs(capsys):
    assert main(["analyze", FIXTURE, "--app-package", "com.visa."]) == 0
    out = capsys.readouterr().out
    assert "Tier-1 report" in out
    assert "distinct call paths merged" in out


def test_json_signals_are_machine_readable(capsys):
    assert main(["analyze", FIXTURE, "--app-package", "com.visa.", "--json"]) == 0
    signals = json.loads(capsys.readouterr().out)
    assert any(s["kind"] == "rate_breach" for s in signals)
    assert all("sample" not in s for s in signals)


def test_events_json_emits_one_object_per_line(capsys):
    assert main(["analyze", FIXTURE, "--app-package", "com.visa.", "--events-json"]) == 0
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) > 1000
    assert json.loads(lines[0])["severity"] in {"INFO", "WARN", "ERROR"}
