import pytest
import analyzer

# findings = [
#     {
#         "rule_id": "SEC002",
#         "description": "Insecure OS Configuration",
#         "file": "os_config.ini"
#     },
#     {
#         "rule_id": "SEC003",
#         "description": "Weak Password Policy",
#         "file": "password_policy.txt"   
#     },
#     {
#         "rule_id": "SEC004" ,
#         "desctiption": "Unencrypted Sensitive Data",
#         "file": "sensitive_data.txt",
        
#     }
# ]

def rule_ids(findings):
    return sorted({f.rule_id for f in findings})

class TestSec002:
    @pytest.mark.parametrize("code", [
        "import os\nos.system('ls' + d)",
        "import os\nos.popen(cmd)",
    ])
    def test_flags_os_shell_calls(self, code):
        assert "SEC002" in rule_ids(analyzer.analyze_source(code, "t.py"))

