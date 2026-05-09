"""
parse_cwe_xml.py

Run this once from your project root to convert the MITRE CWE XML dump
into a flat JSON file used by attack_classifier.py.

Usage:
    python parse_cwe_xml.py

Input:  cwec_v4.20.xml  (in current directory)
Output: output/cwe_db.json
"""

import xml.etree.ElementTree as ET
import json
import os
import re

XML_PATH    = "cwec_v4.20.xml"
OUTPUT_PATH = os.path.join("output", "cwe_db.json")

# MITRE XML namespace
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

# Map MITRE consequence scopes/impacts → our attack_type + severity
CONSEQUENCE_RULES = [
    # (keywords_in_scope_or_impact,           attack_type,                          severity)
    ({"Execute Unauthorized Code", "execute"}, "Remote Code Execution",              "CRITICAL"),
    ({"Gain Privileges", "Bypass Protection"}, "Unauthorized Access",                "CRITICAL"),
    ({"SQL Injection", "Command Injection"},   "Injection Attack",                   "CRITICAL"),
    ({"Read Memory", "Read Files"},            "Sensitive Data Exposure",             "HIGH"),
    ({"Modify Memory", "Modify Files",
      "Modify Application Data"},              "Data Manipulation",                   "HIGH"),
    ({"Read Application Data",
      "Confidentiality"},                      "Sensitive Data Exposure",             "HIGH"),
    ({"Bypass Protection Mechanism"},          "Security Bypass",                     "HIGH"),
    ({"DoS: Crash", "DoS: Resource",
      "Availability", "Unreliable Execution"}, "Denial of Service",                  "MEDIUM"),
    ({"Hide Activities"},                      "Defense Evasion",                     "MEDIUM"),
    ({"Varies by Context"},                    "Varies by Context",                   "MEDIUM"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _infer_attack(consequences: list[dict]) -> tuple[str, str]:
    """
    Given a list of {scope, impact} dicts from MITRE XML,
    returns (attack_type, severity).
    """
    all_text = " ".join(
        f"{c.get('scope', '')} {c.get('impact', '')}"
        for c in consequences
    ).lower()

    best_attack   = "Security Weakness"
    best_severity = "MEDIUM"

    for keywords, attack_type, severity in CONSEQUENCE_RULES:
        if any(kw.lower() in all_text for kw in keywords):
            if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(best_severity, 99):
                best_attack   = attack_type
                best_severity = severity

    return best_attack, best_severity


def parse(xml_path: str) -> dict:
    print(f"[parser] Parsing {xml_path} ...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Try to detect namespace from root tag
    ns_match = re.match(r'\{(.+?)\}', root.tag)
    ns_uri   = ns_match.group(1) if ns_match else "http://cwe.mitre.org/cwe-7"
    NS_      = {"cwe": ns_uri}

    db = {}

    # Weaknesses live under Weaknesses/Weakness
    for weakness in root.iter(f"{{{ns_uri}}}Weakness"):
        cwe_num = weakness.get("ID")
        name    = weakness.get("Name", "Unknown Weakness")
        if not cwe_num:
            continue
        cwe_id = f"CWE-{cwe_num}"

        # Description
        description = ""
        desc_el = weakness.find(f"{{{ns_uri}}}Description")
        if desc_el is not None and desc_el.text:
            description = desc_el.text.strip()

        # Consequences
        consequences = []
        for conseq in weakness.findall(
            f".//{{{ns_uri}}}Common_Consequences/{{{ns_uri}}}Consequence"
        ):
            scope_els  = conseq.findall(f"{{{ns_uri}}}Scope")
            impact_els = conseq.findall(f"{{{ns_uri}}}Impact")
            note_els   = conseq.findall(f"{{{ns_uri}}}Note")

            scopes  = [el.text.strip() for el in scope_els  if el.text]
            impacts = [el.text.strip() for el in impact_els if el.text]
            notes   = [el.text.strip() for el in note_els   if el.text]

            consequences.append({
                "scope":  " / ".join(scopes),
                "impact": " / ".join(impacts),
                "note":   " ".join(notes),
            })

        attack_type, severity = _infer_attack(consequences)

        # Attacker capability: first sentence of description, capped at 100 chars
        cap = description.split(".")[0].strip()
        if len(cap) > 100:
            cap = cap[:97] + "…"
        if not cap:
            cap = f"Exploit {name.lower()} weakness"

        db[cwe_id] = {
            "category":            name,
            "attack_type":         attack_type,
            "attacker_capability": cap,
            "impact":              "; ".join(
                f"{c['scope']}: {c['impact']}" for c in consequences if c["impact"]
            )[:200],
            "severity":            severity,
            "source":              "mitre_xml",
        }

    print(f"[parser] Parsed {len(db)} CWE entries.")
    return db


def main():
    if not os.path.exists(XML_PATH):
        print(f"[parser] ERROR: {XML_PATH} not found in current directory.")
        print(f"         Download from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")
        return

    db = parse(XML_PATH)

    os.makedirs("output", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(db, f, indent=2)

    print(f"[parser] Saved to {OUTPUT_PATH}")
    print(f"[parser] Sample entry:")
    sample_key = next(iter(db))
    print(f"         {sample_key}: {json.dumps(db[sample_key], indent=10)}")


if __name__ == "__main__":
    main()