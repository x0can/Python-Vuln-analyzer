from __future__ import annotations
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator
from typing import Iterable, Iterator
import ast
import json
import re
import argparse
import sys

DANGEROUS_BUILTINS = {"eval", "exec"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox", ".nox", ".eggs", ".idea", ".vscode", "node_modules", "dist", "build"}

SECRET_NAME = re.compile(r"(password|passwd|secret|api_?key|token)$", re.I)

@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def collect_files(root, extensions: set[str] | None = None) -> Iterator[Path]:
    root = Path(root)
    exts = extensions or {".py"}
    if not root.exists():
        raise FileNotFoundError(root)
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts):
            continue
        if path.is_file() and path.suffix in exts:
            yield path


def parse_source(source: str, filename: str) -> ast.Module | None:
    try:
        return ast.parse(source, filename=filename)
    except (SyntaxError, ValueError):
        return None


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _kw(call: ast.Call, name: str):
    return next((kw.value for kw in call.keywords if kw.arg == name), None)

def _is_dynamic_string(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    def _add(self, node, rule, sev, msg):
        self.findings.append(Finding(self.filename, node.lineno, rule, sev, msg))

    def visit_Call(self, node: ast.Call):
        name = _call_name(node.func)
        attr = name.rsplit(".", 1)[-1]

        if name in DANGEROUS_BUILTINS:
            self._add(node, "SEC001", "HIGH", f"Use of {name}() allows code injection")
        elif name in {"os.system", "os.popen"}:
            self._add(node, "SEC002", "HIGH", f"{name}() runs a shell command; use subprocess with a list")
        elif name.startswith("subprocess.") and _is_true(_kw(node, "shell")):
            self._add(node, "SEC003", "HIGH", f"{name}() subprocess called with shell=True")
        elif name in {"pickle.loads", "pickle.load", "marshal.loads"}:
            self._add(node, "SEC004", "HIGH", f"{name}() on untrusted data can execute code")
        elif name == "yaml.load" and _kw(node, "Loader") is None:
            self._add(node, "SEC005", "HIGH", "yaml.load() without a safe Loader; use yaml.safe_load()")
        elif attr in {"execute", "executemany"} and node.args and _is_dynamic_string(node.args[0]):
            self._add(node, "SQL001", "HIGH", "SQL query built from a dynamic string; use parameters")
        self.generic_visit(node)
    
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self._add(node, "ERR001", "MEDIUM", "Bare except: catches everything incl. SystemExit")
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self._add(node, "ERR002", "LOW", "Exception silently swallowed with pass")
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
                    self._add(node, "SEC006", "HIGH", f"Hardcoded secret in '{target.id}'")
        
        self.generic_visit(node)


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def analyze_source(source: str, filename: str) -> list[Finding]:
    tree = parse_source(source, filename)
    if tree is None:
        return [Finding(filename, 0, "PARSE001", "INFO", "File could not be parsed")]
    visitor = SecurityVisitor(filename)
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: f.line)

def analyze_path(path) -> list[Finding]:
    findings: list[Finding] = []
    for file in collect_files(path):
        source = file.read_text(encoding="utf-8", errors="replace")
        findings.extend(analyze_source(source, str(file)))
    return sorted(findings, key=lambda f: (f.file, f.line))

def format_text(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    lines = [f"{f.file}:{f.line}  [{f.severity}] {f.rule_id}  {f.message}" for f in findings]
    lines.append(f"\nTotal findings: {len(findings)}")
    return "\n".join(lines)


def write_report(findings: list[Finding], out, fmt: str = "json") -> None:
    if fmt == "json":
        body = json.dumps({"total": len(findings),
                           "findings": [f.to_dict() for f in findings]}, indent=2)
    elif fmt == "text":
        body = format_text(findings)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    Path(out).write_text(body, encoding="utf-8")
    
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Python security code analyzer")
    parser.add_argument("path")
    parser.add_argument("-o", "--output", help="write report to this file")
    parser.add_argument("-f", "--format", choices=["json", "text"], default="text")
    args = parser.parse_args(argv)

    findings = analyze_path(args.path)
    if args.output:
        write_report(findings, args.output, args.format)
    print(format_text(findings))
    return 1 if findings else 0  # non-zero lets CI fail the build


if __name__ == "__main__":
    sys.exit(main())