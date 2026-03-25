import re

def parse_pyproject_toml(content: str) -> list:
    packages = []

    # PEP 621 style: [project] dependencies = [...]
    pep621_match = re.search(
        r'\[project\].*?dependencies\s*=\s*\[(.*?)\]',
        content, re.DOTALL
    )
    if pep621_match:
        block = pep621_match.group(1)
        for line in block.splitlines():
            line = line.strip().strip('",').strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r'(==|>=|<=|~=|!=|>|<)', line)
            name = parts[0].strip()
            version = parts[2].strip() if len(parts) >= 3 else "unspecified"
            if name:
                packages.append({
                    "name": name.lower(),
                    "version": version,
                    "ecosystem": "pypi"
                })

    # Poetry style: [tool.poetry.dependencies]
    poetry_match = re.search(
        r'\[tool\.poetry\.dependencies\](.*?)(\[|\Z)',
        content, re.DOTALL
    )
    if poetry_match:
        block = poetry_match.group(1)
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().lower()
                version = parts[1].strip().strip('"').strip("'")
                if name == "python":
                    continue
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "pypi"
                })

    return packages