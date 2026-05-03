#!/usr/bin/env python3
"""
tools/sync-metadata-from-compliance-doc.py

One-time (and re-runnable) backfill of PRESTON_META metadata blocks into
legacy check scripts that pre-date the v1.0 metadata schema. Reads the
canonical mappings from COMPLIANCE_MAPPING.md and prepends a YAML metadata
heredoc to each check file that lacks one. Idempotent: skips check files
that already have a PRESTON_META block.

After running, every check has machine-readable framework citations so
the runner's --framework filter works across the full catalog (not just
the crypto suite). Re-run after editing COMPLIANCE_MAPPING.md to roll
forward updates.

Usage:
    python3 tools/sync-metadata-from-compliance-doc.py
    python3 tools/sync-metadata-from-compliance-doc.py --dry-run
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CHECKS_DIR = ROOT / "checks"
MAPPING_FILE = ROOT / "COMPLIANCE_MAPPING.md"

FRAMEWORK_PREFIX = {
    "PCI-DSS v4.0": "PCI-DSS:4.0",
    "SOC 2": "SOC2:TSC-2017",
    "ISO 27001": "ISO-27001:2022",
    "OWASP API": "OWASP-API:2023",
    "NIST CSF": "NIST-CSF:2.0",
    "CIS v8": "CIS-v8",
    "OWASP": "OWASP-Top-10:2021",
}

DEFAULT_FRAMEWORKS = (
    "PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, "
    "OWASP-API:2023, NIST-CSF:2.0, CIS-v8"
)


def parse_compliance_mapping(path: Path) -> dict:
    """Parse COMPLIANCE_MAPPING.md and return dict of P-NN -> {name, description, frameworks}."""
    text = path.read_text()
    sections: dict = {}
    current_id = None
    current_data = None

    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^### (P-\d+):\s*(.+)$", line)
        if m:
            if current_id:
                sections[current_id] = current_data
            current_id = m.group(1)
            current_data = {
                "name": m.group(2).strip(),
                "description": "",
                "frameworks": [],
            }
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and not lines[j].startswith("|") and not lines[j].startswith("###"):
                current_data["description"] = lines[j].strip()
        elif (
            line.startswith("| ")
            and current_id is not None
            and not line.startswith("|---")
            and "Framework" not in line
            and "Status" not in line
        ):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 2:
                fw_name = parts[0]
                requirement = parts[1]
                if fw_name in FRAMEWORK_PREFIX:
                    prefix = FRAMEWORK_PREFIX[fw_name]
                    controls = re.findall(
                        r"(?:API\d+:\d{4}|"
                        r"P\d+\.\d+|"
                        r"[A-Z]{2,3}\d+(?:\.\d+)*|"
                        r"\d+(?:\.\d+){1,3})",
                        requirement,
                    )
                    for ctrl in controls:
                        token = f"{prefix}:{ctrl}"
                        if token not in current_data["frameworks"]:
                            current_data["frameworks"].append(token)
        i += 1

    if current_id:
        sections[current_id] = current_data
    return sections


def filename_to_id(filename: str) -> "str | None":
    """Extract P-NN from filename like '01-hardcoded-secrets.sh'."""
    m = re.match(r"^(\d+)-", filename)
    if not m:
        return None
    num = int(m.group(1))
    if num < 100:
        return f"P-{num:02d}"
    return f"P-{num}"


def has_metadata(check_file: Path) -> bool:
    return "PRESTON_META" in check_file.read_text()


def derive_severity(name: str) -> str:
    name_lower = name.lower()
    critical_kw = ["secret", "private key", "injection", "sql", "auth bypass", "2fa bypass"]
    high_kw = [
        "encryption", "tls", "session", "token", "rate limit", "rate-limit",
        "audit trail", "csrf", "auth", "ssrf", "blacklist", "idempot",
    ]
    medium_kw = [
        "logging", "monitoring", "header", "cors", "validation", "privacy",
        "session", "key management", "mass assignment", "resource limit",
    ]
    if any(w in name_lower for w in critical_kw):
        return "critical"
    if any(w in name_lower for w in high_kw):
        return "high"
    if any(w in name_lower for w in medium_kw):
        return "medium"
    return "medium"


def derive_category(check_id: str, name: str) -> str:
    name_lower = name.lower()
    if "live" in name_lower or "monitoring" in name_lower or check_id == "P-10":
        return "live-monitoring"
    if any(
        w in name_lower
        for w in [
            "evidence", "documentation", "policy", "training",
            "ceremony", "ir plan", "incident response",
        ]
    ):
        return "compliance-evidence"
    if any(
        w in name_lower
        for w in [
            "infrastructure", "aws", "iam", "network", "waf",
            "container", "ci/cd", "deployment",
        ]
    ):
        return "infra-scan"
    return "code-scan"


def derive_runtime_class(check_id: str) -> str:
    if check_id == "P-10":
        return "live-ssh"
    return "static-grep"


def derive_evidence_required(category: str) -> str:
    return "true" if category == "compliance-evidence" else "false"


def title_case_from_filename(filename: str) -> str:
    base = filename[:-3] if filename.endswith(".sh") else filename
    parts = base.split("-", 1)
    if len(parts) > 1:
        words = parts[1].split("-")
        return " ".join(w.capitalize() for w in words)
    return base


def generate_metadata(check_id: str, mapping_data, check_file: Path) -> str:
    if mapping_data and mapping_data.get("name"):
        name = mapping_data["name"]
        description = (
            mapping_data["description"]
            or f"{name} security check; see COMPLIANCE_MAPPING.md for control mapping."
        )
        if mapping_data["frameworks"]:
            frameworks = ", ".join(mapping_data["frameworks"])
        else:
            frameworks = DEFAULT_FRAMEWORKS
    else:
        name = title_case_from_filename(check_file.name)
        description = f"{name} security check (see COMPLIANCE_MAPPING.md for details)."
        frameworks = DEFAULT_FRAMEWORKS

    severity = derive_severity(name)
    category = derive_category(check_id, name)
    runtime = derive_runtime_class(check_id)
    evidence_required = derive_evidence_required(category)
    description_safe = description.replace("\n", " ").replace("|", "/")

    return (
        ": <<'PRESTON_META'\n"
        "schema_version: 1\n"
        f"id: {check_id}\n"
        f"name: {name}\n"
        f"description: {description_safe}\n"
        f"category: {category}\n"
        f"severity: {severity}\n"
        "languages: any\n"
        "min_tier: free\n"
        f"runtime_class: {runtime}\n"
        f"evidence_required: {evidence_required}\n"
        "version: 1.0.0\n"
        "added_in: 0.1.0\n"
        "author_name: Preston-Check Maintainers\n"
        "author_github: prestoncheck\n"
        f"frameworks: {frameworks}\n"
        "PRESTON_META\n"
        "\n"
    )


def prepend_metadata(check_file: Path, metadata: str, dry_run: bool = False) -> None:
    content = check_file.read_text()
    if content.startswith("#!"):
        nl = content.find("\n")
        new_content = content[: nl + 1] + "\n" + metadata + content[nl + 1 :]
    else:
        new_content = "#!/bin/bash\n\n" + metadata + content
    if dry_run:
        print(f"  [DRY] Would write {check_file.name} ({len(new_content) - len(content)} bytes added)")
        return
    check_file.write_text(new_content)


def main() -> int:
    dry_run = "--dry-run" in sys.argv

    sections = parse_compliance_mapping(MAPPING_FILE)
    print(f"Parsed {len(sections)} check sections from COMPLIANCE_MAPPING.md")

    backfilled = 0
    skipped_existing = 0
    used_generic = 0
    used_mapped = 0

    for check_file in sorted(CHECKS_DIR.glob("*.sh")):
        if has_metadata(check_file):
            skipped_existing += 1
            continue

        check_id = filename_to_id(check_file.name)
        if not check_id:
            continue

        mapping = sections.get(check_id)
        if mapping:
            used_mapped += 1
        else:
            used_generic += 1

        metadata = generate_metadata(check_id, mapping, check_file)
        prepend_metadata(check_file, metadata, dry_run=dry_run)
        backfilled += 1

    print()
    print(f"Backfilled:                    {backfilled}")
    print(f"  Used COMPLIANCE_MAPPING.md:  {used_mapped}")
    print(f"  Used generic mapping:        {used_generic}")
    print(f"Skipped (already has meta):    {skipped_existing}")
    if dry_run:
        print("\n(dry run — no files written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
