import xml.etree.ElementTree as ET
import re

MAVEN_NS = "http://maven.apache.org/POM/4.0.0"


def parse_pom_xml(content: str) -> list:
    packages = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        print(f"[java_parser] Failed to parse pom.xml: {e}")
        return packages

    # Step 1: Extract <properties> defined in THIS file only
    properties = {}
    props_node = (
        root.find(f"{{{MAVEN_NS}}}properties") or
        root.find("properties")
    )
    if props_node is not None:
        for child in props_node:
            tag = re.sub(r'\{.*?\}', '', child.tag)
            if child.text and child.text.strip():
                properties[tag] = child.text.strip()

    print(f"[java_parser] Found {len(properties)} local properties")

    # Step 2: Parse all <dependency> blocks
    dependencies = root.findall(f".//{{{MAVEN_NS}}}dependency")
    if not dependencies:
        dependencies = root.findall(".//dependency")

    skipped_test = 0
    skipped_unresolved = 0

    for dep in dependencies:
        group_id    = _find_text(dep, "groupId")
        artifact_id = _find_text(dep, "artifactId")
        version     = _find_text(dep, "version") or "unspecified"
        scope       = _find_text(dep, "scope") or "compile"

        # Skip explicit test/provided scopes
        if scope in ("test", "provided", "system"):
            skipped_test += 1
            continue

        # Try to resolve ${placeholder} versions from local properties
        version = _resolve_property(version, properties)

        # If still unresolved after local lookup, it comes from a parent POM
        # we can't access. These are almost always build/test tools, not
        # runtime deps — skip them and log it.
        if re.search(r'\$\{.+?\}', version):
            print(f"[java_parser] Skipping {group_id}:{artifact_id} "
                  f"— version '{version}' defined in parent POM (not accessible)")
            skipped_unresolved += 1
            continue

        if group_id and artifact_id:
            packages.append({
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "ecosystem": "maven"
            })

    print(f"[java_parser] Skipped {skipped_test} test/provided deps, "
          f"{skipped_unresolved} with unresolvable parent-POM versions")

    return packages


def _resolve_property(value: str, properties: dict) -> str:
    """
    Resolves ${key} placeholders up to 3 passes
    to handle chained references like ${a} -> ${b} -> value.
    """
    for _ in range(3):
        match = re.search(r'\$\{(.+?)\}', value)
        if not match:
            break
        key = match.group(1)
        if key in properties:
            value = value.replace(f"${{{key}}}", properties[key])
        else:
            break
    return value


def _find_text(element, tag: str):
    node = element.find(f"{{{MAVEN_NS}}}{tag}")
    if node is None:
        node = element.find(tag)
    return node.text.strip() if node is not None and node.text else None