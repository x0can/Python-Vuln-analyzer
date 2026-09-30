import analyzer

class TestFinding:
    def test_finding_is_serialisable(self):
        f = analyzer.Finding("a.py", 3, "SEC001", "HIGH", "Use of eval()")
        assert f.to_dict() == {
            "file": "a.py", "line": 3, "rule_id": "SEC001", "severity": "HIGH", "message": "Use of eval()"
        }
        