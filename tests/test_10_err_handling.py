import analyzer


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class TestErrorHandling:
    def test_bare_except_flagged(self):
        code = "try:\n    x()\nexcept:\n    log()"
        assert "ERR001" in rule_ids(analyzer.analyze_source(code, "t.py"))

    def test_swallowed_exception_flagged(self):
        code = "try:\n    x()\nexcept ValueError:\n    pass"
        assert rule_ids(analyzer.analyze_source(code, "t.py")) == ["ERR002"]

    def test_specific_handled_exception_ok(self):
        code = "try:\n    x()\nexcept ValueError as e:\n    log(e)"
        assert analyzer.analyze_source(code, "t.py") == []
