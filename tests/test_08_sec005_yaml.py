import pytest

import analyzer


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class TestSec005:
    def test_flags_yaml_load_without_loader(self):
        code = "import yaml\nyaml.load(data)"
        assert "SEC005" in rule_ids(analyzer.analyze_source(code, "t.py"))

    @pytest.mark.parametrize("safe", [
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)",
        "import yaml\nyaml.safe_load(data)",
    ])
    def test_safe_yaml_not_flagged(self, safe):
        assert analyzer.analyze_source(safe, "t.py") == []
