from pathlib import Path

import analyzer

SAMPLES = Path(__file__).parent / "samples"


class TestCli:
    def test_exit_code_nonzero_when_findings(self, capsys):
        assert analyzer.main([str(SAMPLES / "vulnerable.py")]) == 1

    def test_exit_code_zero_when_clean(self):
        assert analyzer.main([str(SAMPLES / "secure.py")]) == 0

    def test_writes_json_report(self, tmp_path):
        out = tmp_path / "r.json"
        analyzer.main([str(SAMPLES / "vulnerable.py"), "-o", str(out), "-f", "json"])
        assert out.exists()
