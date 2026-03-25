from ingestion.github_client import (
    parse_github_url,
    get_file_tree,
    find_dependency_files,
    get_file_content
)
from ingestion.parsers.python_parser import parse_requirements_txt
from ingestion.parsers.toml_parser import parse_pyproject_toml
from ingestion.parsers.node_parser import parse_package_lock
from ingestion.parsers.node_package_parser import parse_package_json
from ingestion.parsers.java_parser import parse_pom_xml
from ingestion.parsers.gradle_parser import parse_gradle


PARSER_MAP = {
    "requirements.txt":  parse_requirements_txt,
    "pyproject.toml":    parse_pyproject_toml,
    "package-lock.json": parse_package_lock,
    "package.json":      parse_package_json,
    "pom.xml":           parse_pom_xml,
    "build.gradle":      parse_gradle,
    "build.gradle.kts":  parse_gradle,
}


def ingest(github_url: str) -> list:
    print(f"\n[ingestion] Starting for: {github_url}")

    owner, repo = parse_github_url(github_url)
    print(f"[ingestion] Repo: {owner}/{repo}")

    all_files = get_file_tree(owner, repo)
    print(f"[ingestion] Total files in repo: {len(all_files)}")

    dep_files = find_dependency_files(all_files)
    if not dep_files:
        print("[ingestion] No supported dependency files found.")
        return []

    print(f"[ingestion] Dependency files found ({len(dep_files)}):")
    for f in dep_files:
        print(f"  - {f}")

    all_packages = []
    for file_path in dep_files:
        filename = file_path.split("/")[-1]
        parser = PARSER_MAP.get(filename)
        if not parser:
            continue

        print(f"\n[ingestion] Parsing: {file_path}")
        try:
            content = get_file_content(owner, repo, file_path)
            packages = parser(content)
            print(f"[ingestion] Found {len(packages)} packages")
            all_packages.extend(packages)
        except Exception as e:
            # Don't let one bad file crash the whole run
            print(f"[ingestion] ERROR parsing {file_path}: {e}")
            continue

    # Deduplicate by name + ecosystem
    seen = set()
    unique_packages = []
    for pkg in all_packages:
        key = (pkg["name"], pkg["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    print(f"\n[ingestion] Total unique packages: {len(unique_packages)}")
    return unique_packages