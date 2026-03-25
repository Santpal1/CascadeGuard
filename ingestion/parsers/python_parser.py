import re

def parse_requirements_txt(content: str) -> list:
    packages = []
    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("-"):
            continue

        line = line.split("#")[0].strip()

        parts = re.split(r"(==|>=|<=|~=|!=|>|<)", line)
        name = parts[0].strip()
        version = parts[2].strip() if len(parts) >= 3 else "unspecified"

        if name:
            packages.append({
                "name": name.lower(),
                "version": version,
                "ecosystem": "pypi"
            })

    return packages