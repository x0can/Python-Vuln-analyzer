import pytest

import analyzer

class TestCollectFiles:
    def test_finds_python_files_recursively(self, tmp_path):
        (tmp_path/ "pkg").mkdir()
        (tmp_path/ "a.py").write_text("x = 1")
        (tmp_path/ "pkg"/ "b.py").write_text("y = 2")   
        (tmp_path/ "notes.txt").write_text("ignore me")
        names = sorted(p.name for p in analyzer.collect_files(tmp_path))
        assert names == ["a.py", "b.py"]
    
    def test_custom_extensions(self, tmp_path):
        (tmp_path / "a.py").write_text("")
        (tmp_path / "b.pyw").write_text("")
        names = sorted(p.name for p in analyzer.collect_files(tmp_path, extensions={".pyw"}))
        assert names == ["b.pyw"]

    def test_skips_virtualenv_and_cache_dirs(self, tmp_path):
        for d in ("venv", ".git", "__pycache__"):
            (tmp_path / d).mkdir()
            (tmp_path / d / "x.py").write_text("")
        assert list(analyzer.collect_files(tmp_path)) == []

    def test_single_file_path_is_accepted(self, tmp_path):
        f = tmp_path / "one.py"
        f.write_text("")
        assert list(analyzer.collect_files(f)) == [f]

    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            list(analyzer.collect_files(tmp_path / "nope"))