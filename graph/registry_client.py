import requests
import time

# Simple in-memory cache so we don't re-fetch the same package twice
# across recursive calls
_cache = {}


def get_dependencies(name: str, version: str, ecosystem: str) -> list:
    """
    Fetches the direct dependencies of a given package from its registry.
    Returns a list of {name, version, ecosystem} dicts — same format
    as Module 1 output so the graph builder can treat them uniformly.
    """
    cache_key = f"{ecosystem}:{name}:{version}"
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        if ecosystem == "pypi":
            result = _pypi_deps(name, version)
        elif ecosystem == "npm":
            result = _npm_deps(name, version)
        elif ecosystem == "maven":
            result = _maven_deps(name, version)
        else:
            result = []
    except Exception as e:
        print(f"[registry] ERROR fetching {ecosystem}:{name}:{version} — {e}")
        result = []

    _cache[cache_key] = result
    return result


# ─── PyPI ────────────────────────────────────────────────────────────────────

def _pypi_deps(name: str, version: str) -> list:
    """
    Queries PyPI JSON API for a package's dependencies.
    If version is 'unspecified', fetches the latest release.
    """
    if version == "unspecified":
        url = f"https://pypi.org/pypi/{name}/json"
    else:
        # Normalize version — strip specifiers like >=, ==
        clean = _clean_version(version)
        url = f"https://pypi.org/pypi/{name}/{clean}/json"

    response = requests.get(url, timeout=10)
    if response.status_code == 404:
        # Version not found — fall back to latest
        response = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
    if not response.ok:
        return []

    data = response.json()
    requires = data.get("info", {}).get("requires_dist") or []

    packages = []
    for req in requires:
        # Format: "werkzeug>=2.0.0" or "click ; extra == 'dev'"
        # Strip environment markers and extras
        req = req.split(";")[0].strip()
        req = req.split("[")[0].strip()  # strip extras like requests[security]

        import re
        parts = re.split(r"(==|>=|<=|~=|!=|>|<|\s)", req, maxsplit=1)
        dep_name = parts[0].strip().lower()
        if dep_name:
            packages.append({
                "name": dep_name,
                "version": "unspecified",  # let registry resolve on next level
                "ecosystem": "pypi"
            })

    return packages


# ─── npm ─────────────────────────────────────────────────────────────────────

def _npm_deps(name: str, version: str) -> list:
    """
    Queries the npm registry for a package's dependencies.
    """
    if version == "unspecified":
        url = f"https://registry.npmjs.org/{name}/latest"
    else:
        clean = _clean_version(version)
        url = f"https://registry.npmjs.org/{name}/{clean}"

    response = requests.get(url, timeout=10)
    if response.status_code == 404:
        response = requests.get(
            f"https://registry.npmjs.org/{name}/latest", timeout=10
        )
    if not response.ok:
        return []

    data = response.json()
    deps = data.get("dependencies", {})

    packages = []
    for dep_name, dep_version in deps.items():
        clean = dep_version.lstrip("^~>=< ")
        packages.append({
            "name": dep_name,
            "version": clean or "unspecified",
            "ecosystem": "npm"
        })

    return packages


# ─── Maven ───────────────────────────────────────────────────────────────────

def _maven_deps(name: str, version: str) -> list:
    """
    Queries Maven Central for a package's POM and extracts its dependencies.
    name format: groupId:artifactId
    """
    if ":" not in name:
        return []

    group_id, artifact_id = name.split(":", 1)
    group_path = group_id.replace(".", "/")

    # Resolve latest version if unspecified
    if version == "unspecified":
        version = _maven_latest_version(group_id, artifact_id)
        if not version:
            return []

    clean = _clean_version(version)
    pom_url = (
        f"https://repo1.maven.org/maven2/"
        f"{group_path}/{artifact_id}/{clean}/"
        f"{artifact_id}-{clean}.pom"
    )

    response = requests.get(pom_url, timeout=10)
    if not response.ok:
        return []

    # Reuse our existing POM parser
    from ingestion.parsers.java_parser import parse_pom_xml
    return parse_pom_xml(response.text)


def _maven_latest_version(group_id: str, artifact_id: str) -> str | None:
    """
    Queries Maven Central search API to find the latest version of a package.
    """
    url = (
        f"https://search.maven.org/solrsearch/select"
        f"?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
    )
    try:
        response = requests.get(url, timeout=10)
        if not response.ok:
            return None
        docs = response.json().get("response", {}).get("docs", [])
        if docs:
            return docs[0].get("latestVersion")
    except Exception:
        return None
    return None


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _clean_version(version: str) -> str:
    """
    Strips version specifiers to get a bare version number.
    '>=2.0.0' -> '2.0.0'
    '~=3.1.2' -> '3.1.2'
    """
    import re
    cleaned = re.sub(r'^[^0-9]*', '', version)
    # Take only the first version if there's a range like ">=1.0,<2.0"
    cleaned = cleaned.split(",")[0].strip()
    return cleaned or version