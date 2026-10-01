import pytest
import analyzer

def rule_ids(findings):
    return sorted({f.rule_id for f in findings})

class TestSec004:
    @pytest.mark.parametrize("code", [
        "import pickle\npickle.loads(blob)",
        "import pickle\npickle.load(fh)",
    ])
    def test_flags_pickle(self, code):
        assert "SEC004" in rule_ids(analyzer.analyze_source(code, "t.py"))