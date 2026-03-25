import json

def parse_package_lock(content: str) -> list:
    packages = []
    data = json.loads(content)
    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 3:
        raw = data.get("packages", {})
        for key, info in raw.items():
            if not key:
                continue
            name = key.replace("node_modules/", "").split("node_modules/")[-1]
            version = info.get("version", "unspecified")
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": "npm"
            })
    else:
        raw = data.get("dependencies", {})
        for name, info in raw.items():
            version = info.get("version", "unspecified")
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": "npm"
            })

    return packages