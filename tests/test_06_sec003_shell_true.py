import pytest
import analyzer

def rule_ids(findings):
    return sorted({f.rule_id for f in findings})

class TestSec003:
    def test_flgas_shell_true(self):
        code = "import subprocess\nsubprocess.run('cmd', shell=True)"
        assert "SEC003" in rule_ids(analyzer.analyze_source(code, "t.py"))
        
    @pytest.mark.parametrize("safe", [
        "import subprocess\nsubprocess.run(['ls'], d)",
        "import subprocess\nsubprocess.run(cmd, shell=False)",
    ])
    def test_safe_subprocess_not_flagged(self, safe):
        assert analyzer.analyze_source(safe, "t.py") == []