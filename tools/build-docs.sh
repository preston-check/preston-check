#!/bin/bash
###############################################################################
# tools/build-docs.sh — Render every Markdown doc under docs/ to HTML + PDF.
#
# Output structure mirrors the source layout, lands under docs/_rendered/:
#   docs/_rendered/<path>/<name>.html
#   docs/_rendered/<path>/<name>.pdf
#
# Requires: pandoc + Google Chrome (or wkhtmltopdf as fallback).
# Idempotent: re-running re-renders everything from current sources.
###############################################################################

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS="$ROOT/docs"
OUT="$DOCS/_rendered"

# Pick a PDF renderer
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ -x "$CHROME" ]]; then
  PDF_CMD="chrome"
elif command -v wkhtmltopdf >/dev/null 2>&1; then
  PDF_CMD="wkhtmltopdf"
else
  echo "warn: no PDF renderer found (Chrome or wkhtmltopdf). Will produce HTML only." >&2
  PDF_CMD="none"
fi

command -v pandoc >/dev/null || { echo "error: pandoc not installed"; exit 1; }

mkdir -p "$OUT"

# Embedded CSS — mirrors the public landing page's design tokens so
# rendered docs feel like part of the same product family. Single
# self-contained stylesheet inlined into every HTML output.
CSS=$(cat <<'CSS'
:root {
  --ink: #0B1F3A; --paper: #FFFFFF; --paper-2: #F8FAFC; --rule: #E2E8F0;
  --mute: #475569; --mute-2: #94A3B8; --accent: #10B981; --accent-2: #2563EB;
  --bad: #DC2626; --warn: #F59E0B;
  --serif: ui-serif, Georgia, "Times New Roman", serif;
  --sans: ui-sans-serif, system-ui, -apple-system, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body { font-family: var(--sans); font-size: 16px; line-height: 1.65; color: var(--ink);
       max-width: 780px; margin: 48px auto; padding: 0 32px; background: var(--paper);
       -webkit-font-smoothing: antialiased; }
h1, h2, h3, h4 { font-family: var(--serif); font-weight: 600; color: var(--ink);
                 letter-spacing: -0.01em; line-height: 1.2; margin: 1.4em 0 0.5em; }
h1 { font-size: 38px; border-bottom: 2px solid var(--rule); padding-bottom: 0.3em;
     margin-top: 0; }
h2 { font-size: 26px; border-bottom: 1px solid var(--rule); padding-bottom: 0.2em; }
h3 { font-size: 20px; }
h4 { font-size: 17px; }
p { margin: 0 0 1em; }
a { color: var(--accent-2); text-decoration: none; }
a:hover { text-decoration: underline; }
code { font-family: var(--mono); font-size: 0.9em; background: var(--paper-2);
       padding: 1px 6px; border-radius: 4px; border: 1px solid var(--rule); }
pre { font-family: var(--mono); font-size: 13px; background: var(--ink); color: #E2E8F0;
      padding: 16px 20px; border-radius: 8px; overflow-x: auto; line-height: 1.5; }
pre code { background: transparent; padding: 0; border: 0; color: inherit; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 14px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--rule); }
thead th { background: var(--paper-2); font-weight: 600; font-size: 12px; text-transform: uppercase;
           letter-spacing: 1px; color: var(--mute-2); border-bottom: 2px solid var(--rule); }
tbody tr:hover { background: var(--paper-2); }
ul, ol { margin: 0.6em 0 1em 1.6em; padding: 0; }
li { margin: 0.3em 0; }
blockquote { margin: 1em 0; padding: 0.5em 1.2em; border-left: 4px solid var(--accent);
             background: var(--paper-2); color: var(--mute); font-style: italic; }
hr { border: 0; border-top: 1px solid var(--rule); margin: 2em 0; }
.title-block-header { padding-bottom: 16px; margin-bottom: 24px; border-bottom: 2px solid var(--ink); }
.title-block-header h1 { border-bottom: 0; padding-bottom: 0; }
.title-block-header .subtitle { color: var(--mute); font-size: 17px; font-style: italic; }
.title-block-header .author, .title-block-header .date { color: var(--mute-2); font-size: 13px; }
@media print {
  body { max-width: none; margin: 0; padding: 24px; font-size: 11pt; }
  pre, code { font-size: 10pt; }
  h1 { page-break-before: auto; }
  h2 { page-break-after: avoid; }
}
CSS
)

render_one() {
  local src="$1"
  local rel="${src#$DOCS/}"
  local base="${rel%.md}"
  local out_html="$OUT/${base}.html"
  local out_pdf="$OUT/${base}.pdf"

  mkdir -p "$(dirname "$out_html")"

  # Inline the CSS via --include-in-header so the HTML is self-contained.
  local css_tmp; css_tmp=$(mktemp)
  printf '<style>\n%s\n</style>\n' "$CSS" > "$css_tmp"

  # Title from frontmatter or filename
  local title
  title=$(awk -F': *' '/^title:/{gsub(/^"|"$/, "", $2); print $2; exit}' "$src" 2>/dev/null || true)
  [[ -z "$title" ]] && title=$(basename "$src" .md)

  pandoc "$src" \
    --from markdown \
    --to html5 \
    --standalone \
    --include-in-header="$css_tmp" \
    --metadata title="$title" \
    -o "$out_html" 2>/dev/null

  rm -f "$css_tmp"

  if [[ "$PDF_CMD" == "chrome" ]]; then
    "$CHROME" --headless --disable-gpu --no-margins \
      --print-to-pdf="$out_pdf" "file://$out_html" 2>/dev/null
  elif [[ "$PDF_CMD" == "wkhtmltopdf" ]]; then
    wkhtmltopdf --quiet "$out_html" "$out_pdf" 2>/dev/null
  fi

  printf '  %-60s html %4dKB pdf %4dKB\n' \
    "${rel}" \
    $(($(stat -f%z "$out_html" 2>/dev/null || stat -c%s "$out_html") / 1024)) \
    $([[ -f "$out_pdf" ]] && echo $(($(stat -f%z "$out_pdf" 2>/dev/null || stat -c%s "$out_pdf") / 1024)) || echo 0)
}

count=0
echo "Rendering docs to $OUT/"
echo "PDF renderer: $PDF_CMD"
echo ""

# Render every .md file under docs/, except _rendered itself.
while IFS= read -r f; do
  render_one "$f"
  count=$((count + 1))
done < <(find "$DOCS" -type f -name '*.md' -not -path "$OUT/*" | sort)


# Generate a top-level index.html linking every rendered doc.
{
  printf '<!doctype html><html lang="en"><head><meta charset="utf-8"/>'
  printf '<title>Preston-Check Documentation</title>'
  printf '<style>%s</style></head><body>' "$CSS"
  printf '<h1>Preston-Check Documentation</h1>'
  printf '<p>Every Markdown doc under <code>docs/</code> rendered to HTML and PDF. '
  printf 'Source-of-truth is the Markdown in the repo; this directory is '
  printf 'regenerated on every <code>tools/build-docs.sh</code> run.</p>'
  for section in manuals strategy state-of-fintech-security ""; do
    if [[ -z "$section" ]]; then
      printf '<h2>Top-level</h2><ul>'
      find "$OUT" -maxdepth 1 -name '*.html' ! -name 'index.html' | sort | while read -r f; do
        rel="${f#$OUT/}"
        base="${rel%.html}"
        title=$(grep -oE '<h1[^>]*>[^<]+</h1>' "$f" | head -1 | sed 's/<[^>]*>//g')
        [[ -z "$title" ]] && title="$base"
        pdf="${base}.pdf"
        printf '<li><a href="%s">%s</a> &middot; <a href="%s">PDF</a></li>' "$rel" "$title" "$pdf"
      done
      printf '</ul>'
    elif [[ -d "$OUT/$section" ]]; then
      printf '<h2>%s</h2><ul>' "$section"
      find "$OUT/$section" -name '*.html' | sort | while read -r f; do
        rel="${f#$OUT/}"
        base="${rel%.html}"
        title=$(grep -oE '<h1[^>]*>[^<]+</h1>' "$f" | head -1 | sed 's/<[^>]*>//g')
        [[ -z "$title" ]] && title="$base"
        pdf="${base}.pdf"
        printf '<li><a href="%s">%s</a> &middot; <a href="%s">PDF</a></li>' "$rel" "$title" "$pdf"
      done
      printf '</ul>'
    fi
  done
  printf '<hr/><p style="color:var(--mute-2);font-size:13px;">Rendered %s &middot; '
  printf 'See the <a href="https://github.com/preston-check/preston-check">source</a> for the canonical Markdown.</p>' \
    "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '</body></html>'
} > "$OUT/index.html"

echo ""
echo "Rendered $count docs to $OUT/"
echo "Index at file://$OUT/index.html"
