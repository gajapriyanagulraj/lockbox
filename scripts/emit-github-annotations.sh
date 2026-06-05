#!/usr/bin/env bash
set -euo pipefail

SCAN_REPORT="${1:-artifacts/scan-report.json}"
LIMIT="${2:-10}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to emit GitHub annotations." >&2
  exit 1
fi

jq -r --argjson limit "$LIMIT" '
  [.Results[]?.Vulnerabilities[]?]
  | sort_by(
      if .Severity == "CRITICAL" then 0
      elif .Severity == "HIGH" then 1
      elif .Severity == "MEDIUM" then 2
      elif .Severity == "LOW" then 3
      else 4 end
    )
  | .[:$limit]
  | .[]
  | @base64
' "$SCAN_REPORT" | while IFS= read -r row; do
  vuln="$(printf "%s" "$row" | base64 --decode)"
  severity="$(printf "%s" "$vuln" | jq -r '.Severity // "UNKNOWN"')"
  cve="$(printf "%s" "$vuln" | jq -r '.VulnerabilityID // "UNKNOWN"')"
  package="$(printf "%s" "$vuln" | jq -r '.PkgName // "unknown"')"
  installed="$(printf "%s" "$vuln" | jq -r '.InstalledVersion // "unknown"')"
  fixed="$(printf "%s" "$vuln" | jq -r '.FixedVersion // "not fixed"')"
  title="$(printf "%s" "$vuln" | jq -r '(.Title // .Description // "No title") | gsub("[\r\n]"; " ") | .[0:180]')"

  if [ "$severity" = "CRITICAL" ] || [ "$severity" = "HIGH" ]; then
    echo "::error title=$severity $cve::$package $installed -> fixed: $fixed. $title"
  else
    echo "::warning title=$severity $cve::$package $installed -> fixed: $fixed. $title"
  fi
done
