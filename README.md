# Python Vuln Analyzer

A lightweight static analysis tool that scans Python code for common security vulnerabilities and risky coding patterns.

It parses source files into an abstract syntax tree (AST) using Python's built-in `ast` module, so it understands code structure instead of just matching text. That lets it tell `eval(user_input())` apart from a safe `ast.literal_eval(s)`.

The project was built with **test-driven development (TDD)**: every rule was written test-first (red → green), including tests that make sure safe code is **not** flagged.

## Features

- Scans a single file or a whole directory, recursively
- Skips virtual environments, caches and build folders (`venv`, `.venv`, `__pycache__`, `node_modules`, `dist`, `build` and more)
- Reports each finding with **file, line number, rule ID, severity and message**
- Text output in the terminal, plus optional **JSON** or **text** report files
- Exits with code `1` when findings exist and `0` when clean, so it can **fail a CI build**
- Handles files that cannot be parsed without crashing (reported as `PARSE001`)
- No third-party dependencies at runtime (standard library only)

## Detection rules

| Rule | Severity | What it detects |
|---|---|---|
| `SEC001` | HIGH | `eval()` / `exec()`, which allow code injection |
| `SEC002` | HIGH | `os.system()` / `os.popen()`, which run shell commands |
| `SEC003` | HIGH | `subprocess.*` called with `shell=True` |
| `SEC004` | HIGH | `pickle.load(s)` / `marshal.loads` on possibly untrusted data (insecure deserialization) |
| `SEC005` | HIGH | `yaml.load()` without a safe `Loader` |
| `SEC006` | HIGH | Hardcoded secrets in variables named like `password`, `secret`, `api_key`, `token` |
| `SQL001` | HIGH | SQL queries built from dynamic strings (`+`, `%`, `.format()`, f-strings) passed to `execute()` / `executemany()` |
| `ERR001` | MEDIUM | Bare `except:` that also catches `SystemExit` and `KeyboardInterrupt` |
| `ERR002` | LOW | Exceptions silently swallowed with `pass` |
| `PARSE001` | INFO | File could not be parsed |

## Requirements

- Python 3.10+
- `pytest` (only for running the tests)

## Usage

```bash
# Scan a directory and print findings
python analyzer.py path/to/project

# Scan a single file
python analyzer.py app.py

# Save a JSON report
python analyzer.py path/to/project -o report.json -f json

# Save a text report
python analyzer.py path/to/project -o report.txt -f text
```

### Example output

```
app/views.py:12  [HIGH] SEC001  Use of eval() allows code injection
app/db.py:40  [HIGH] SQL001  SQL query built from a dynamic string; use parameters
app/utils.py:88  [MEDIUM] ERR001  Bare except: catches everything incl. SystemExit

Total findings: 3
```

### JSON report format

```json
{
  "total": 1,
  "findings": [
    {
      "file": "app/views.py",
      "line": 12,
      "rule_id": "SEC001",
      "severity": "HIGH",
      "message": "Use of eval() allows code injection"
    }
  ]
}
```

### Use in CI

Because the tool exits with a non-zero code when it finds issues, it can block a pull request:

```yaml
- name: Security scan
  run: python analyzer.py src/
```

## Real-world test: OWASP PyGoat

The analyzer was run against [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat), an intentionally vulnerable Django application. It reported **43 findings**:

| Severity | Count | Examples |
|---|---|---|
| HIGH | 8 | `eval`/`exec` code injection, `shell=True`, insecure `pickle` deserialization, unsafe `yaml.load` |
| MEDIUM | 30 | Bare `except:` blocks |
| LOW | 5 | Silently swallowed exceptions |

Findings came from areas such as the broken authentication lab, the insecure deserialization lab, the SSRF playground and the main views.

## Running the tests

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install pytest
pytest
```

The suite has **14 test files and 48 tests**, built step by step:

1. `Finding` data model
2. File collection and skip rules
3. Safe parsing
4. One test file per rule (`SEC001`–`SEC006`, `SQL001`, `ERR001`/`ERR002`), each with vulnerable **and** safe examples
5. Whole-directory analysis on `tests/samples/vulnerable.py` and `tests/samples/secure.py`
6. JSON and text reporting
7. Command-line interface and exit codes

## Project structure

```
analyzer.py        # the analyzer and CLI
tests/             # pytest suite (test_01 ... test_14)
tests/samples/     # vulnerable.py and secure.py fixtures
pytest.ini         # pytest configuration
```

## Limitations

- Pattern-based: it flags risky calls but does not trace data flow, so some findings need manual review
- Python only
- Secret detection relies on variable names and string literals

## Roadmap

- More rules (for example `requests` with `verify=False`, weak hashing such as `md5`/`sha1`, `tempfile.mktemp`)
- Inline suppression comments for accepted risks
- SARIF output for GitHub code scanning

## Author

Alex Mwaura · [github.com/x0can](https://github.com/x0can)
