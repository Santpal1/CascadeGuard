import re


def parse_gradle(content: str) -> list:
    """
    Parses build.gradle (Groovy DSL) and build.gradle.kts (Kotlin DSL).

    Handles the most common dependency declaration patterns:

    Groovy DSL:
        implementation 'com.google.guava:guava:32.0.1-jre'
        implementation "org.springframework:spring-core:6.0.0"
        implementation group: 'commons-io', name: 'commons-io', version: '2.11.0'

    Kotlin DSL:
        implementation("com.google.guava:guava:32.0.1-jre")
        implementation(group = "commons-io", name = "commons-io", version = "2.11.0")

    Does NOT parse version catalog references (libs.guava) or
    dynamic versions (latest.release, 1.+) — marks those as unspecified.
    """
    packages = []

    # Scopes we care about — runtime/compile time deps only
    RUNTIME_SCOPES = {
        "implementation",
        "api",
        "compile",
        "runtimeOnly",
        "compileOnly",
    }

    # Skip these scopes entirely
    SKIP_SCOPES = {
        "testImplementation",
        "testCompile",
        "testRuntimeOnly",
        "testCompileOnly",
        "androidTestImplementation",
        "debugImplementation",
        "releaseImplementation",
    }

    seen = set()

    # --- Pattern 1: Short string notation ---
    # implementation 'group:artifact:version'
    # implementation("group:artifact:version")
    pattern_string = re.compile(
        r'(\w+)\s*[\s(]["\']'
        r'([a-zA-Z0-9_.\-]+)'   # group
        r':'
        r'([a-zA-Z0-9_.\-]+)'   # artifact
        r'(?::([a-zA-Z0-9_.\-@+]+))?'  # version (optional)
        r'["\']'
    )

    for match in pattern_string.finditer(content):
        scope = match.group(1)
        group = match.group(2)
        artifact = match.group(3)
        version = match.group(4) or "unspecified"

        if scope in SKIP_SCOPES:
            continue
        if scope not in RUNTIME_SCOPES:
            continue

        # Skip dynamic versions
        if version in ("latest.release", "latest.integration") or \
                version.endswith("+") or version.startswith("$"):
            version = "unspecified"

        name = f"{group}:{artifact}"
        key = (name, "maven")
        if key not in seen:
            seen.add(key)
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": "maven"
            })

    # --- Pattern 2: Map/named notation ---
    # implementation group: 'x', name: 'y', version: 'z'
    # implementation(group = "x", name = "y", version = "z")
    pattern_map = re.compile(
        r'(\w+)\s*[\s(]'
        r'(?:group\s*[:=]\s*["\']([a-zA-Z0-9_.\-]+)["\'])'
        r'.*?'
        r'(?:name\s*[:=]\s*["\']([a-zA-Z0-9_.\-]+)["\'])'
        r'.*?'
        r'(?:version\s*[:=]\s*["\']([a-zA-Z0-9_.\-@+]+)["\'])?',
        re.DOTALL
    )

    for match in pattern_map.finditer(content):
        scope = match.group(1)
        group = match.group(2)
        artifact = match.group(3)
        version = match.group(4) or "unspecified"

        if scope in SKIP_SCOPES:
            continue
        if scope not in RUNTIME_SCOPES:
            continue

        name = f"{group}:{artifact}"
        key = (name, "maven")
        if key not in seen:
            seen.add(key)
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": "maven"
            })

    return packages