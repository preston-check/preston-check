#!/usr/bin/env python3
"""Build the distributable Preston-Check AI add-on package.

Produces dist/preston-check-ai-addon-<version>.tar.gz (+ .sha256): a
self-contained tree — scanner, full check catalog, personas, MCP
server, installer, manual — that works from any extraction point (the
package mirrors the repo layout the server resolves against). Version
comes from the newest v* git tag and is stamped into the packaged
scanner, matching what release.yml does for the main tarball.

Personas are regenerated first so the package can never ship stale
compiled artifacts. The manual is included as markdown and, when pandoc
and weasyprint are available, as a PDF whose CSS keeps table headers
repeating across page breaks and never splits a row mid-page (per the
project PDF pagination rule). Missing PDF tooling is logged, not fatal.

Stdlib only. Usage: python3 tools/build_ai_addon_package.py
"""

import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIST = REPO / "dist"

PDF_CSS = """
@page { size: A4; margin: 2cm; }
body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
       font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }
h1, h2, h3 { page-break-after: avoid; }
pre, code { font-family: Menlo, Consolas, monospace; font-size: 9pt; }
pre { background: #f6f8fa; padding: 8px; page-break-inside: avoid;
      white-space: pre-wrap; }
table { border-collapse: collapse; width: 100%; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left;
         vertical-align: top; }
th { background: #f0f0f0; }
"""


def version() -> str:
    tag = subprocess.run(
        ["git", "-C", str(REPO), "tag", "--list", "v*", "--sort=-v:refname"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    return tag[0].lstrip("v") if tag else "0.0.0-dev"


def build_pdf(manual_md: Path, out_pdf: Path) -> bool:
    if not (shutil.which("pandoc") and shutil.which("weasyprint")):
        print("note: pandoc/weasyprint not found — MANUAL.pdf skipped")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        html = Path(tmp) / "manual.html"
        css = Path(tmp) / "manual.css"
        css.write_text(PDF_CSS, encoding="utf-8")
        subprocess.run(
            ["pandoc", str(manual_md), "-f", "gfm", "-s",
             "--metadata", "title=Preston-Check AI Add-on — Owner's Manual",
             "-o", str(html)],
            check=True,
        )
        subprocess.run(
            ["weasyprint", "-s", str(css), str(html), str(out_pdf)],
            check=True,
        )
    return True


def main() -> int:
    ver = version()
    name = f"preston-check-ai-addon-{ver}"
    print(f"building {name}")

    print("regenerating personas from the catalog ...")
    subprocess.run([sys.executable, str(REPO / "tools" / "build_personas.py")], check=True)

    with tempfile.TemporaryDirectory(prefix="preston-pkg-") as tmp:
        root = Path(tmp) / name
        root.mkdir()

        for d in ("checks", "lib", "lang"):
            shutil.copytree(REPO / d, root / d)
        shutil.copytree(REPO / "ai-addon" / "mcp", root / "ai-addon" / "mcp")
        shutil.copytree(REPO / "ai-addon" / "personas", root / "ai-addon" / "personas")
        for f in ("config.yml", "LICENSE", "NOTICE"):
            shutil.copy2(REPO / f, root / f)
        shutil.copy2(REPO / "ai-addon" / "README.md", root / "ai-addon" / "README.md")
        # Manual and installer surface at the package root for discoverability.
        shutil.copy2(REPO / "ai-addon" / "MANUAL.md", root / "MANUAL.md")
        shutil.copy2(REPO / "ai-addon" / "install-ai-addon.sh", root / "install-ai-addon.sh")

        scanner = (REPO / "preston-check.sh").read_text(encoding="utf-8")
        scanner, n = re.subn(
            r'^PRESTON_VERSION="[^"]*"', f'PRESTON_VERSION="{ver}"',
            scanner, count=1, flags=re.M,
        )
        if n != 1:
            print("error: PRESTON_VERSION line not found in preston-check.sh")
            return 1
        (root / "preston-check.sh").write_text(scanner, encoding="utf-8")
        (root / "preston-check.sh").chmod(0o755)
        (root / "VERSION").write_text(ver + "\n", encoding="utf-8")

        pdf_ok = build_pdf(root / "MANUAL.md", root / "MANUAL.pdf")

        DIST.mkdir(exist_ok=True)
        tarball = DIST / f"{name}.tar.gz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(root, arcname=name)

    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    (DIST / f"{name}.tar.gz.sha256").write_text(
        f"{digest}  {tarball.name}\n", encoding="utf-8"
    )
    size_mb = tarball.stat().st_size / 1_048_576
    print(f"{tarball}  ({size_mb:.1f} MB, pdf={'yes' if pdf_ok else 'no'})")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
