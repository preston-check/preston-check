#!/usr/bin/env python3
"""
tools/sync-metadata-from-compliance-doc.py

Re-runnable backfill of PRESTON_META metadata blocks into legacy check
scripts that pre-date the v1.0 metadata schema. Reads canonical mappings
from COMPLIANCE_MAPPING.md and prepends a YAML metadata heredoc to each
check file that lacks one.

Idempotent on default: skips check files that already have a PRESTON_META
block. Pass --force-legacy to strip and regenerate metadata for legacy
IDs (P-001..P-280) — useful after fixing parser bugs. Crypto suite
(P-301..P-360) is never touched by --force-legacy.

Usage:
    python3 tools/sync-metadata-from-compliance-doc.py
    python3 tools/sync-metadata-from-compliance-doc.py --dry-run
    python3 tools/sync-metadata-from-compliance-doc.py --force-legacy
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
}

# Per-framework regex extractors. Order matters: first match wins per token.
# Each pattern captures the control identifier WITHOUT any redundant version
# already implied by the prefix.
FRAMEWORK_PATTERNS = {
    "PCI-DSS v4.0": re.compile(r"\b(\d+(?:\.\d+){1,3})\b"),
    "SOC 2":        re.compile(r"\b([A-Z]{1,2}\d+(?:\.\d+)+|P\d+\.\d+)\b"),
    "ISO 27001":    re.compile(r"\bA?\.?(\d+\.\d+)\b"),
    "OWASP API":    re.compile(r"\b(API\d+)(?::\d{4})?\b"),
    "NIST CSF":     re.compile(r"\b([A-Z]{2}\.[A-Z]{2}-\d+(?:\.\d+)?|[A-Z]{2,3}\.[A-Z]{2,3}-\d+)\b"),
    "CIS v8":       re.compile(r"\b(\d+(?:\.\d+){1,2})\b"),
}

DEFAULT_FRAMEWORKS = (
    "PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, "
    "OWASP-API:2023, NIST-CSF:2.0, CIS-v8"
)


def parse_compliance_mapping(path: Path) -> dict:
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
                    pat = FRAMEWORK_PATTERNS.get(fw_name)
                    if pat:
                        for match in pat.finditer(requirement):
                            ctrl = match.group(1)
                            token = f"{prefix}:{ctrl}"
                            if token not in current_data["frameworks"]:
                                current_data["frameworks"].append(token)
        i += 1

    if current_id:
        sections[current_id] = current_data
    return sections


def filename_to_id(filename: str):
    m = re.match(r"^(\d+)-", filename)
    if not m:
        return None
    num = int(m.group(1))
    if num < 100:
        return f"P-{num:02d}"
    return f"P-{num}"


def is_legacy_id(check_id: str) -> bool:
    """True for legacy IDs (P-01..P-103, P-200..P-280); False for crypto suite (P-301..P-360)."""
    m = re.match(r"P-(\d+)", check_id)
    if not m:
        return False
    return int(m.group(1)) <= 280


def has_metadata(check_file: Path) -> bool:
    return "PRESTON_META" in check_file.read_text()


def strip_existing_metadata(content: str) -> str:
    """Remove the first PRESTON_META heredoc block if present."""
    pattern = r": <<'PRESTON_META'\n.*?\nPRESTON_META\n+"
    return re.sub(pattern, "", content, count=1, flags=re.DOTALL)


def derive_severity(name: str) -> str:
    name_lower = name.lower()
    if any(w in name_lower for w in ["secret", "private key", "injection", "sql", "auth bypass", "2fa bypass"]):
        return "critical"
    if any(w in name_lower for w in [
        "encryption", "tls", "session", "token", "rate limit", "rate-limit",
        "audit trail", "csrf", "auth", "ssrf", "blacklist", "idempot",
    ]):
        return "high"
    if any(w in name_lower for w in [
        "logging", "monitoring", "header", "cors", "validation", "privacy",
        "session", "key management", "mass assignment", "resource limit",
    ]):
        return "medium"
    return "medium"


def derive_category(check_id: str, name: str) -> str:
    name_lower = name.lower()
    if "live" in name_lower or "monitoring" in name_lower or check_id == "P-10":
        return "live-monitoring"
    if any(w in name_lower for w in [
        "evidence", "documentation", "policy", "training",
        "ceremony", "ir plan", "incident response",
    ]):
        return "compliance-evidence"
    if any(w in name_lower for w in [
        "infrastructure", "aws", "iam", "network", "waf",
        "container", "ci/cd", "deployment",
    ]):
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
        return " ".join(w.capitalize() for w in parts[1].split("-"))
    return base


def generate_metadata(check_id: str, mapping_data, check_file: Path) -> str:
    if mapping_data and mapping_data.get("name"):
        name = mapping_data["name"]
        description = mapping_data["description"] or f"{name} security check; see COMPLIANCE_MAPPING.md for control mapping."
        frameworks = ", ".join(mapping_data["frameworks"]) if mapping_data["frameworks"] else DEFAULT_FRAMEWORKS
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


def write_with_metadata(check_file: Path, metadata: str, force: bool, dry_run: bool) -> None:
    content = check_file.read_text()
    if force and "PRESTON_META" in content:
        content = strip_existing_metadata(content)
    if content.startswith("#!"):
        nl = content.find("\n")
        new_content = content[: nl + 1] + "\n" + metadata + content[nl + 1 :]
    else:
        new_content = "#!/bin/bash\n\n" + metadata + content
    if dry_run:
        return
    check_file.write_text(new_content)


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    force_legacy = "--force-legacy" in sys.argv

    sections = parse_compliance_mapping(MAPPING_FILE)
    print(f"Parsed {len(sections)} check sections from COMPLIANCE_MAPPING.md")

    backfilled = 0
    overwritten = 0
    skipped_existing = 0
    skipped_crypto = 0
    used_generic = 0
    used_mapped = 0

    for check_file in sorted(CHECKS_DIR.glob("*.sh")):
        check_id = filename_to_id(check_file.name)
        if not check_id:
            continue
        already = has_metadata(check_file)

        if already and not (force_legacy and is_legacy_id(check_id)):
            if not is_legacy_id(check_id):
                skipped_crypto += 1
            else:
                skipped_existing += 1
            continue

        mapping = sections.get(check_id)
        if mapping:
            used_mapped += 1
        else:
            used_generic += 1

        metadata = generate_metadata(check_id, mapping, check_file)
        write_with_metadata(check_file, metadata, force=already, dry_run=dry_run)
        if already:
            overwritten += 1
        else:
            backfilled += 1

    print()
    print(f"Newly backfilled:              {backfilled}")
    print(f"Overwritten (--force-legacy):  {overwritten}")
    print(f"  Used COMPLIANCE_MAPPING.md:  {used_mapped}")
    print(f"  Used generic mapping:        {used_generic}")
    print(f"Skipped (legacy already meta): {skipped_existing}")
    print(f"Skipped (crypto suite):        {skipped_crypto}")
    if dry_run:
        print("\n(dry run — no files written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
