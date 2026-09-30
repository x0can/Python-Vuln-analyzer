from __future__ import annotations
from dataclasses import asdict,dataclass
from pathlib import Path
from typing import Iterator
import ast

DANGEROUS_BUILTINS = {"eval", "exec"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox", ".nox", ".eggs", ".idea", ".vscode", "node_modules", "dist", "build"}

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


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    def _add(self, node, rule, sev, msg):
        self.findings.append(Finding(self.filename, node.lineno, rule, sev, msg))
    
    def visit_Call(self, node: ast.Call):
        name = _call_name(node.func)
        
        if name in DANGEROUS_BUILTINS:
            self._add(node, "SEC001", "HIGH", f"Use of {name}() allows code injection")
        self.generic_visit(node)
        

def analyze_source(source: str, filename: str) -> list[Finding]:
    tree = parse_source(source, filename)
    if tree is None:
        return [Finding(filename, 0, "PARSE001", "INFO", "File could not be parsed")]
    visitor = SecurityVisitor(filename)
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: f.line)