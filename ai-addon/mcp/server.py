#!/usr/bin/env python3
"""Preston-Check MCP server — the scanner as drop-in LLM tools.

Speaks MCP over stdio (newline-delimited JSON-RPC 2.0): initialize,
tools/list, tools/call, ping. Stdlib only; shells out to the real
preston-check.sh so findings are deterministic scanner evidence, never
model recall. See docs/ai-addon.md.

Load into Claude Code:
    claude mcp add preston-check -- python3 <repo>/ai-addon/mcp/server.py
Any other MCP client: command = python3, args = [.../server.py].

Self-test (no client needed):
    python3 ai-addon/mcp/server.py --selftest
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SCANNER = REPO / "preston-check.sh"
CHECK_DIRS = {  # tier -> directory (proposed excluded: unverified detections)
    "core": REPO / "checks",
    "verified": REPO / "checks" / "community" / "verified",
    "accepted": REPO / "checks" / "community" / "accepted",
}
PROTOCOL_FALLBACK = "2025-06-18"
REPORT_CAP = 40_000
SOURCE_CAP = 20_000
ANSI = re.compile(r"\x1b\[[0-9;]*m")

TOOLS = [
    {
        "name": "scan_path",
        "description": (
            "Run the deterministic Preston-Check security scanner against a "
            "directory. Returns per-check PASS/FAIL/WARN/SKIP results with "
            "file:line evidence, scorecard counts, and the markdown report. "
            "Use this as ground truth before asserting any security finding."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (absolute, or ~ expanded).",
                },
                "mode": {
                    "type": "string",
                    "enum": ["light", "full"],
                    "description": "light = core P-01..P-20 (~30s, default); full = entire catalog (~3min).",
                },
                "severity": {
                    "type": "string",
                    "description": "Only run checks of these severities, comma-separated: critical,high,medium,low,info.",
                },
                "framework": {
                    "type": "string",
                    "description": "Only run checks whose metadata references this framework (e.g. PCI-DSS, SOC2, MiCA).",
                },
                "category": {
                    "type": "string",
                    "description": "Filter by category: code-scan, compliance-evidence, infra-scan, live-monitoring.",
                },
                "include_proposed": {
                    "type": "boolean",
                    "description": "Also run UNVERIFIED early-warning checks (findings labelled [UNVERIFIED]). Default false.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_checks",
        "description": (
            "List Preston-Check catalog checks with parsed metadata (id, name, "
            "severity, CWE, category, compliance frameworks). Paginated; the "
            "result reports total so nothing is silently capped."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tier": {
                    "type": "string",
                    "enum": ["core", "verified", "accepted", "all"],
                    "description": "Catalog tier to list (default all).",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter to one severity: critical, high, medium, low or info.",
                },
                "framework_contains": {
                    "type": "string",
                    "description": "Substring match against the frameworks metadata (e.g. PCI-DSS).",
                },
                "limit": {"type": "integer", "description": "Page size, default 50, max 200."},
                "offset": {"type": "integer", "description": "Page offset, default 0."},
            },
        },
    },
    {
        "name": "explain_check",
        "description": (
            "Return one check's full metadata and its actual detection source "
            "code, so explanations of what the test does are grounded in the "
            "script rather than recall."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "check_id": {
                    "type": "string",
                    "description": "Check id from metadata, e.g. P-01 or P-1157.",
                }
            },
            "required": ["check_id"],
        },
    },
]


def scanner_version() -> str:
    m = re.search(r'^PRESTON_VERSION="([^"]+)"', SCANNER.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "unknown"


def parse_meta(path: Path) -> dict | None:
    """Extract the PRESTON_META key/value block, mirroring lib/check_metadata.sh."""
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<<.?'?PRESTON_META'?\n(.*?)\nPRESTON_META\s*$", text, re.S | re.M)
    if not m:
        return None
    meta = {}
    for line in m.group(1).splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip()
    return meta


def iter_checks(tier: str = "all"):
    for t, d in CHECK_DIRS.items():
        if tier not in ("all", t) or not d.is_dir():
            continue
        for path in sorted(d.glob("*.sh")):
            meta = parse_meta(path)
            if meta and meta.get("id"):
                yield t, path, meta


def text_result(text: str, structured: dict | None = None, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def tool_scan_path(args: dict) -> dict:
    target = Path(os.path.expanduser(args["path"])).resolve()
    if not target.is_dir():
        return text_result(f"not a directory: {target}", is_error=True)
    mode = args.get("mode", "light")
    with tempfile.TemporaryDirectory(prefix="preston-mcp-") as tmp:
        config = Path(tmp) / "config.yml"
        config.write_text(f"app_name: mcp-scan\nsource_dir: {target}\n", encoding="utf-8")
        report = Path(tmp) / "report.md"
        cmd = [
            "bash", str(SCANNER), "--config", str(config), "--report", str(report),
            "--ci-soft", "--airgap", "--light" if mode == "light" else "--full",
        ]
        if args.get("severity"):
            cmd += ["--severity", args["severity"]]
        if args.get("framework"):
            cmd += ["--framework", args["framework"]]
        if args.get("category"):
            cmd += ["--category", args["category"]]
        if args.get("include_proposed"):
            cmd.append("--include-proposed")
        try:
            proc = subprocess.run(
                cmd, cwd=str(target), capture_output=True, text=True,
                timeout=180 if mode == "light" else 600,
            )
        except subprocess.TimeoutExpired:
            return text_result(f"scan timed out ({mode} mode) on {target}", is_error=True)
        stdout = ANSI.sub("", proc.stdout)

        counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
        findings: list[str] = []
        capture = False
        for line in stdout.splitlines():
            m = re.match(r"^\[\s*(PASS|FAIL|WARN|SKIP)\]\s+(.*)$", line)
            if m:
                counts[m.group(1)] += 1
                capture = m.group(1) in ("FAIL", "WARN")
                if capture:
                    findings.append(f"[{m.group(1)}] {m.group(2).rstrip()}")
            elif capture and line.startswith("         "):
                findings.append("    " + line.strip())
            else:
                capture = False
        if sum(counts.values()) == 0:
            tail = "\n".join(stdout.splitlines()[-25:])
            return text_result(
                f"scanner produced no check results (exit {proc.returncode}).\n"
                f"stdout tail:\n{tail}\nstderr tail:\n{proc.stderr[-2000:]}",
                is_error=True,
            )

        report_text = report.read_text(encoding="utf-8", errors="replace") if report.is_file() else ""
        if len(report_text) > REPORT_CAP:
            report_text = report_text[:REPORT_CAP] + (
                f"\n\n[report truncated at {REPORT_CAP} chars — "
                f"{len(report_text) - REPORT_CAP} more; re-run with filters for the rest]"
            )
        total = sum(counts.values())
        summary = (
            f"Preston-Check v{scanner_version()} scan of {target} ({mode} mode): "
            f"{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['WARN']} WARN, "
            f"{counts['SKIP']} SKIP of {total} checks."
        )
        body = summary
        if findings:
            body += "\n\nFindings:\n" + "\n".join(findings)
        if report_text:
            body += "\n\n---\n" + report_text
        return text_result(body, structured={"target": str(target), "mode": mode, **counts, "total": total})


def tool_list_checks(args: dict) -> dict:
    tier = args.get("tier", "all")
    severity = (args.get("severity") or "").lower()
    needle = (args.get("framework_contains") or "").lower()
    limit = max(1, min(int(args.get("limit", 50)), 200))
    offset = max(0, int(args.get("offset", 0)))
    rows = []
    for t, path, meta in iter_checks(tier):
        if severity and meta.get("severity", "").lower() != severity:
            continue
        if needle and needle not in meta.get("frameworks", "").lower():
            continue
        rows.append(
            {
                "id": meta["id"],
                "name": meta.get("name", ""),
                "severity": meta.get("severity", ""),
                "category": meta.get("category", ""),
                "cwe": meta.get("cwe", ""),
                "frameworks": meta.get("frameworks", ""),
                "tier": t,
                "file": str(path.relative_to(REPO)),
            }
        )
    page = rows[offset : offset + limit]
    payload = {"total": len(rows), "offset": offset, "returned": len(page), "checks": page}
    return text_result(json.dumps(payload, indent=2), structured=payload)


def tool_explain_check(args: dict) -> dict:
    wanted = args["check_id"].strip().lower()
    for t, path, meta in iter_checks("all"):
        if meta["id"].lower() == wanted:
            source = path.read_text(encoding="utf-8", errors="replace")
            if len(source) > SOURCE_CAP:
                source = source[:SOURCE_CAP] + "\n[source truncated]"
            body = (
                f"# {meta['id']} — {meta.get('name', '')} ({t} tier)\n\n"
                f"metadata:\n{json.dumps(meta, indent=2)}\n\n"
                f"detection source ({path.relative_to(REPO)}):\n```bash\n{source}\n```"
            )
            return text_result(body, structured={"metadata": meta, "tier": t, "file": str(path.relative_to(REPO))})
    return text_result(f"no check with id {args['check_id']!r} in core/verified/accepted tiers", is_error=True)


TOOL_HANDLERS = {
    "scan_path": tool_scan_path,
    "list_checks": tool_list_checks,
    "explain_check": tool_explain_check,
}


def handle(msg: dict) -> dict | None:
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if msg_id is None:  # notification — nothing to answer
        return None
    if method == "initialize":
        requested = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_FALLBACK
        result = {
            "protocolVersion": requested,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "preston-check", "version": scanner_version()},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            return rpc_error(msg_id, -32602, f"unknown tool: {name}")
        try:
            result = handler(params.get("arguments") or {})
        except (KeyError, ValueError, OSError) as exc:
            result = text_result(f"{type(exc).__name__}: {exc}", is_error=True)
    elif method == "ping":
        result = {}
    else:
        return rpc_error(msg_id, -32601, f"method not found: {method}")
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def rpc_error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def serve() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            print(json.dumps(rpc_error(None, -32700, "parse error")), flush=True)
            continue
        response = handle(msg)
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


def selftest() -> int:
    failures = []

    def expect(label, cond):
        print(("ok  " if cond else "FAIL") + f" {label}")
        if not cond:
            failures.append(label)

    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": PROTOCOL_FALLBACK}})
    expect("initialize", init["result"]["serverInfo"]["name"] == "preston-check")

    listing = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    expect("tools/list has 3 tools", len(listing["result"]["tools"]) == 3)

    lc = tool_list_checks({"severity": "critical", "limit": 5})
    expect("list_checks finds critical checks", lc["structuredContent"]["total"] > 0)

    ex = tool_explain_check({"check_id": "P-01"})
    expect("explain_check P-01", not ex["isError"] and "Hardcoded" in ex["content"][0]["text"])

    with tempfile.TemporaryDirectory(prefix="preston-fixture-") as fixture:
        # P-01's main branch scans fixed source roots (Client/src etc.);
        # the Go branch scans the whole tree. Plant one secret in each.
        client_src = Path(fixture) / "Client" / "src"
        client_src.mkdir(parents=True)
        (client_src / "settings.py").write_text(
            'password = "super-secret-prod-value"\n', encoding="utf-8"
        )
        (Path(fixture) / "main.go").write_text(
            'package main\n\nvar password = "hunter2-production"\n', encoding="utf-8"
        )
        scan = tool_scan_path({"path": fixture, "mode": "light", "severity": "critical"})
        sc = scan.get("structuredContent") or {}
        expect("scan_path runs", not scan["isError"])
        expect("scan_path detects planted secrets",
               sc.get("FAIL", 0) >= 1 and sc.get("WARN", 0) >= 1)

    print(("selftest PASS" if not failures else f"selftest FAIL: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(serve())
