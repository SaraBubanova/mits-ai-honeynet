"""Smoke tests: cheap checks that catch a broken setup early."""

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SKIP_DIRS = {
    ".git", ".github", ".venv", "venv", "env", "__pycache__",
    ".ruff_cache", ".pytest_cache", "node_modules", "tests",
}

# Imports that are allowed to be missing (optional features)
OPTIONAL: set[str] = set()


def python_files():
    return sorted(
        p for p in ROOT.rglob("*.py")
        if not SKIP_DIRS & set(p.relative_to(ROOT).parts)
    )


def local_names():
    """Names of our own modules/folders, so we don't treat them as third-party packages."""
    names = set()
    for path in python_files():
        names.add(path.stem)
        names.update(path.relative_to(ROOT).parts[:-1])
    return names


def imported_top_level_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_third_party_imports_are_installed():
    local = local_names()
    stdlib = sys.stdlib_module_names
    missing = {}
    for path in python_files():
        for name in imported_top_level_names(path):
            if name in stdlib or name in local or name in OPTIONAL:
                continue
            if importlib.util.find_spec(name) is None:
                missing.setdefault(name, []).append(str(path.relative_to(ROOT)))

    details = "\n".join(
        f"  {name}  (used in: {', '.join(files)})" for name, files in sorted(missing.items())
    )
    assert not missing, (
        "These packages are imported but not installed. "
        "Add them to requirements.txt:\n" + details
    )


def test_honeynet_package_imports():
    importlib.import_module("honeynet")