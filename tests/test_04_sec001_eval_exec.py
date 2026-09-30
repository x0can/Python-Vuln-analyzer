import pytest
import analyzer

def rule_ids(findings):
    return sorted(f.rule_id for f in findings)

class TestSec001:
    @pytest.mark.parametrize("code", ["eval(user_input())", "exec(code)"])
    def test_flags_eval_exec(self, code):
        assert "SEC001" in rule_ids(analyzer.analyze_source(code, "t.py"))
        
    def test_line_number_is_accurate(self):
        code = "x = 1\n\neval(x)\n"
        (f,) = analyzer.analyze_source(code, "t.py")
        assert f.line == 3 and f.file == "t.py"
    
    @pytest.mark.parametrize("safe", [
        "import ast\nast.literal_eval(s)",
        "import json\njson.loads(s)",
    ])
    def test_safe_alternatives(self, safe):
        assert analyzer.analyze_source(safe, "t.py") == []
        
    
    
    