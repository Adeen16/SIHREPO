"""
tests/test_passive_safety.py
-----------------------------
Static AST scan that fails if runtime packages import or call
any active-network primitives.

Scanned packages: ingestion/, processing/, detection/, ml/, api/
(api/ server-socket code is excluded via an explicit allowlist).

Excluded from scan (dev-time helpers): scripts/download_*.py
"""
import ast
import pathlib
import pytest

# Banned symbols — any Name or Attribute use of these in runtime code
BANNED_NAMES = {
    "send", "sendp", "sr", "sr1", "srp", "srp1", "sniff",
    "gethostbyname", "gethostbyaddr", "getaddrinfo",
    "resolve",           # dns.resolver
}

# Packages/files to scan
SCAN_ROOTS = [
    "ingestion",
    "processing",
    "detection",
    "ml",
]

# Files inside api/ that are allowed to use sockets (the server itself)
API_SOCKET_ALLOWLIST = {
    "api/app.py",
    "api/runner.py",
    "api/state.py",
}


def _collect_files(root: pathlib.Path):
    if not root.exists():
        return
    for f in root.rglob("*.py"):
        yield f


def _scan_file(path: pathlib.Path):
    """Return list of (line, col, symbol) violations."""
    violations = []
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return violations  # broken file: let pytest handle it separately
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            violations.append((node.lineno, node.col_offset, node.id))
        elif isinstance(node, ast.Attribute) and node.attr in BANNED_NAMES:
            violations.append((node.lineno, node.col_offset, node.attr))
    return violations


@pytest.mark.parametrize("root", SCAN_ROOTS)
def test_no_active_network_in_runtime_package(root, pytestconfig):
    repo_root = pathlib.Path(pytestconfig.rootdir)
    pkg = repo_root / root
    if not pkg.exists():
        pytest.skip(f"Package {root}/ does not yet exist")

    all_violations = {}
    for f in _collect_files(pkg):
        hits = _scan_file(f)
        if hits:
            rel = f.relative_to(repo_root)
            all_violations[str(rel)] = hits

    if all_violations:
        msg = "Active-network primitives found in runtime packages:\n"
        for path, hits in all_violations.items():
            for line, col, sym in hits:
                msg += f"  {path}:{line}:{col} — '{sym}'\n"
        pytest.fail(msg)


def test_api_routes_no_active_network(pytestconfig):
    """api/routes.py and api/models.py are not in the server-socket allowlist
    and must not use banned names."""
    repo_root = pathlib.Path(pytestconfig.rootdir)
    api_dir = repo_root / "api"
    if not api_dir.exists():
        pytest.skip("api/ does not yet exist")

    all_violations = {}
    for f in api_dir.glob("*.py"):
        rel = str(f.relative_to(repo_root))
        if rel in API_SOCKET_ALLOWLIST:
            continue
        hits = _scan_file(f)
        if hits:
            all_violations[rel] = hits

    if all_violations:
        msg = "Active-network primitives found in non-allowlisted api/ files:\n"
        for path, hits in all_violations.items():
            for line, col, sym in hits:
                msg += f"  {path}:{line}:{col} — '{sym}'\n"
        pytest.fail(msg)
