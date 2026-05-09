"""
AST Scanner - Extracts imports and function definitions from source code.

Supports:
- Python files: ast module for precise parsing
- JavaScript/TypeScript: regex-based parsing for require() and import statements
"""

import ast
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def scan_repository(repo_files: Dict[str, str]) -> Dict:
    """
    Scans repository files to extract imports, functions, and entry points.
    
    Args:
        repo_files: Dict of {filename: file_content_string}
                   Typically fetched from GitHub API
    
    Returns:
        {
            "filename.py": {
                "imports": ["flask", "requests"],
                "functions": ["login()", "process_payment()"],
                "is_entry_point": True/False
            },
            ...
        }
    """
    results = {}
    
    for filename, content in repo_files.items():
        try:
            if filename.endswith(".py"):
                results[filename] = _scan_python_file(filename, content)
            elif filename.endswith((".js", ".ts", ".jsx", ".tsx")):
                results[filename] = _scan_javascript_file(filename, content)
            else:
                # Skip unsupported file types
                continue
                
        except Exception as e:
            logger.warning(f"[ast_scanner] Failed to scan {filename}: {e}")
            continue
    
    return results


def _scan_python_file(filename: str, content: str) -> Dict:
    """
    Scans a Python file using the ast module.
    Extracts imports (both 'import x' and 'from x import y').
    """
    scan_result = {
        "imports": [],
        "functions": [],
        "is_entry_point": _is_entry_point(filename)
    }
    
    try:
        tree = ast.parse(content)
    except SyntaxError:
        logger.debug(f"[ast_scanner] Syntax error in {filename}, skipping")
        return scan_result
    
    imports = set()
    functions = set()
    
    for node in ast.walk(tree):
        # Handle 'import x' and 'import x as y'
        if isinstance(node, ast.Import):
            for alias in node.names:
                # Get the top-level package name
                pkg_name = alias.name.split(".")[0]
                imports.add(pkg_name.lower())
        
        # Handle 'from x import y'
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                # Get the top-level package name
                pkg_name = node.module.split(".")[0]
                imports.add(pkg_name.lower())
        
        # Extract top-level function definitions
        elif isinstance(node, ast.FunctionDef) and _is_top_level(node, tree):
            functions.add(f"{node.name}()")
    
    scan_result["imports"] = sorted(list(imports))
    scan_result["functions"] = sorted(list(functions))
    
    return scan_result


def _scan_javascript_file(filename: str, content: str) -> Dict:
    """
    Scans a JavaScript/TypeScript file using regex.
    Extracts require() and import statements.
    """
    scan_result = {
        "imports": [],
        "functions": [],
        "is_entry_point": _is_entry_point(filename)
    }
    
    imports = set()
    
    # Pattern for: require('package') or require("package")
    require_pattern = r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
    for match in re.finditer(require_pattern, content):
        pkg = match.group(1).strip()
        pkg_name = _extract_js_package_name(pkg)
        if pkg_name:
            imports.add(pkg_name.lower())
    
    # Pattern for: import x from 'package' or import 'package'
    import_pattern = r"import\s+(?:(?:\w+|\{[^}]+\})\s+from\s+)?['\"]([^'\"]+)['\"]"
    for match in re.finditer(import_pattern, content):
        pkg = match.group(1).strip()
        pkg_name = _extract_js_package_name(pkg)
        if pkg_name:
            imports.add(pkg_name.lower())
    
    # Extract function declarations (simple regex, not perfect but good enough)
    func_pattern = r"(?:async\s+)?function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
    functions = set()
    for match in re.finditer(func_pattern, content):
        func_name = match.group(1) or match.group(2)
        if func_name and not func_name[0].isupper():  # Skip class names
            functions.add(f"{func_name}()")
    
    scan_result["imports"] = sorted(list(imports))
    scan_result["functions"] = sorted(list(functions))
    
    return scan_result


def _extract_js_package_name(import_path: str) -> Optional[str]:
    """
    Extracts the package name from a JavaScript import path.
    
    Examples:
        "@scope/package" -> "@scope/package"
        "@scope/package/submodule" -> "@scope/package"
        "lodash" -> "lodash"
        "lodash/map" -> "lodash"
        "./local/module" -> None (local import, skip)
        "../parent" -> None (local import, skip)
    """
    if not import_path:
        return None
    
    # Skip local imports
    if import_path.startswith("."):
        return None
    
    # Handle scoped packages (@scope/package)
    if import_path.startswith("@"):
        parts = import_path.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return parts[0]
    
    # Handle regular packages (get the root package name)
    return import_path.split("/")[0]


def _is_entry_point(filename: str) -> bool:
    """
    Determines if a file is likely an entry point.
    Entry points: main.py, index.js, app.js, server.js, etc.
    """
    name_lower = filename.lower()
    
    entry_point_names = {
        "main.py", "index.js", "index.ts", "app.js", "app.ts",
        "server.js", "server.ts", "index.jsx", "index.tsx",
        "app.jsx", "app.tsx", "server.jsx", "server.tsx",
        "start.js", "start.ts", "run.py", "cli.py"
    }
    
    return any(
        name_lower.endswith(entry) for entry in entry_point_names
    )


def _is_top_level(node: ast.FunctionDef, tree: ast.Module) -> bool:
    """
    Checks if a function node is at the top level (not nested).
    """
    for item in tree.body:
        if item is node:
            return True
    return False
