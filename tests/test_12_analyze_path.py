from pathlib import Path

import analyzer

SAMPLES = Path(__file__).parent / "samples"


class TestSamples:
    def test_vulnerable_sample_has_every_rule(self):
        found = {f.rule_id for f in analyzer.analyze_path(SAMPLES / "vulnerable.py")}
        assert found >= {"SEC001", "SEC002", "SEC003", "SEC004",
                         "SEC005", "SEC006", "SQL001", "ERR001", "ERR002"}

    def test_secure_sample_is_clean(self):
        assert analyzer.analyze_path(SAMPLES / "secure.py") == []

    def test_findings_sorted_by_file_then_line(self):
        findings = analyzer.analyze_path(SAMPLES)
        keys = [(f.file, f.line) for f in findings]
        assert keys == sorted(keys)
