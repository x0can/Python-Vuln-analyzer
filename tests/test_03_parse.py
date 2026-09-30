import analyzer

def rule_ids(findings):
    return sorted({f.rule_id for f in findings})

class TestParseSource:
    def test_valid_code_returns_ast(self):
        import ast
        assert isinstance(analyzer.parse_source("x = 1", "f.py"), ast.Module)
    
    def test_syntax_error_returns_none_not_crash(self):
        assert analyzer.parse_source("def broken(:", "f.py") is None
    
    def test_syntax_error_is_reported_as_finding(self):
        findings = analyzer.analyze_source("def broken(:", "bad.py")
        assert rule_ids(findings) == ["PARSE001"]