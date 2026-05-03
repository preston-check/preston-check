#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-433
name: OWASP LLM04 — Data and Model Poisoning
description: Detects fine-tuning or RAG pipelines that ingest user-controlled or untrusted data without provenance tracking, integrity checks, or content moderation. Poisoned training/retrieval data corrupts downstream LLM behavior in ways that surface as routine bugs.
category: code-scan
severity: medium
languages: typescript, javascript, python, java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-LLM-Top-10:2025:LLM04, NIST-CSF:2.0:PR.DS
false_positive_rate: high
performance_class: fast
origin: OWASP LLM Top 10 (2025) LLM04 — Data and Model Poisoning.
PRESTON_META

echo "P-433: LLM Data Poisoning"

SRC="${SOURCE_DIR:-.}"
rag=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" \
  -iE "vectorStore|embeddings|chromadb|pinecone|weaviate|qdrant|fineTune|fine[_-]tune|retrieve.*chunk" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -z "$rag" ]] && { record "SKIP" "P-433 LLM data poisoning" "No RAG / fine-tune pipeline detected"; return 0 2>/dev/null || true; }
moderation=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" \
  -iE "contentModeration|moderation\.create|safetyChecker|provenance|content[_-]hash|integrity[_-]check" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$moderation" ]] && record "PASS" "P-433 LLM data poisoning" "$(echo "$moderation" | wc -l | tr -d ' ') content moderation / integrity reference(s)" \
  || record "WARN" "P-433 LLM data poisoning" "RAG / fine-tune detected without content moderation or provenance checks"
