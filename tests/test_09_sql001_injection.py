import pytest

import analyzer


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class TestSql001:
    @pytest.mark.parametrize("query", [
        'cur.execute(f"SELECT * FROM users WHERE id={uid}")',
        'cur.execute("SELECT * FROM users WHERE id=%s" % uid)',
        'cur.execute("SELECT * FROM users WHERE id=" + uid)',
        'cur.execute("SELECT * FROM users WHERE id={}".format(uid))',
    ])
    def test_flags_string_built_queries(self, query):
        assert rule_ids(analyzer.analyze_source(query, "t.py")) == ["SQL001"]

    def test_parameterised_query_is_safe(self):
        code = 'cur.execute("SELECT * FROM users WHERE id=?", (uid,))'
        assert analyzer.analyze_source(code, "t.py") == []

    def test_constant_query_is_safe(self):
        assert analyzer.analyze_source('cur.execute("SELECT 1")', "t.py") == []
