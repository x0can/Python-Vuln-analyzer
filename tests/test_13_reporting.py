import json

import pytest

import analyzer


class TestReporting:
    def test_json_report(self, tmp_path):
        out = tmp_path / "report.json"
        analyzer.write_report([analyzer.Finding("a.py", 1, "SEC001", "HIGH", "eval")], out, fmt="json")
        data = json.loads(out.read_text())
        assert data["total"] == 1
        assert data["findings"][0]["rule_id"] == "SEC001"

    def test_text_report_contains_location(self, tmp_path):
        out = tmp_path / "report.txt"
        analyzer.write_report([analyzer.Finding("a.py", 7, "SQL001", "HIGH", "SQLi")], out, fmt="text")
        assert "a.py:7" in out.read_text()

    def test_unknown_format_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            analyzer.write_report([], tmp_path / "r", fmt="xml")
