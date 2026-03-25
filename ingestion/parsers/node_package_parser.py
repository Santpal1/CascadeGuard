import json

def parse_package_json(content: str) -> list:
    packages = []
    data = json.loads(content)

    for section in ["dependencies", "devDependencies"]:
        for name, version in data.get(section, {}).items():
            clean_version = version.lstrip("^~>=<")
            packages.append({
                "name": name,
                "version": clean_version,
                "ecosystem": "npm"
            })

    return packages