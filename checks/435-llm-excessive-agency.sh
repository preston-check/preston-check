#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-435
name: OWASP LLM06 — Excessive Agency
description: Detects LLM agents with broad tool access (database write, money movement, email send) without human-in-the-loop confirmation or per-action authorization. An LLM that can move money without confirmation will eventually move it incorrectly.
category: code-scan
severity: high
languages: typescript, javascript, python, java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-LLM-Top-10:2025:LLM06, NIST-CSF:2.0:PR.AC
false_positive_rate: high
performance_class: fast
origin: OWASP LLM Top 10 (2025) LLM06 — Excessive Agency. Becomes acute as agentic frameworks mature.
PRESTON_META

echo "P-435: LLM Excessive Agency"

SRC="${SOURCE_DIR:-.}"
agents=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" \
  -iE "AgentExecutor|AutoGPT|crewai|langgraph|autogen|tool[_-]calling|function[_-]calling|use[_-]tool|registerTool" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -z "$agents" ]] && { record "SKIP" "P-435 LLM excessive agency" "No agent / tool-calling pattern detected"; return 0 2>/dev/null || true; }
hitl=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" \
  -iE "humanInTheLoop|human[_-]approval|requireConfirmation|interrupt[_-]agent|approval[_-]callback|human[_-]review" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hitl" ]] && record "PASS" "P-435 LLM excessive agency" "$(echo "$hitl" | wc -l | tr -d ' ') human-in-the-loop reference(s)" \
  || record "WARN" "P-435 LLM excessive agency" "Agent / tool-calling detected without human-in-the-loop confirmation"
