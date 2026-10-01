import pytest

import analyzer


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class TestHardcodedSecrets:
    @pytest.mark.parametrize("code", [
        'password = "hunter2"',
        'API_KEY = "sk-123456"',
        'db_secret_token = "abc"',
    ])
    def test_flags_string_literal_secrets(self, code):
        assert rule_ids(analyzer.analyze_source(code, "t.py")) == ["SEC006"]

    @pytest.mark.parametrize("code", [
        'password = os.environ["PASSWORD"]',
        'password = ""',
        'password_hint = "your pet name"',
    ])
    def test_non_secrets_not_flagged(self, code):
        assert analyzer.analyze_source(code, "t.py") == []
