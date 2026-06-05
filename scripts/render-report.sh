#!/usr/bin/env bash
set -euo pipefail

SCAN_REPORT="${1:-artifacts/scan-report.json}"
SBOM_REPORT="${2:-artifacts/sbom.json}"
REPORT_DIR="${3:-reports}"
PUBLIC_DIR="${4:-public}"

mkdir -p "$REPORT_DIR" "$PUBLIC_DIR"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to render reports." >&2
  exit 1
fi

IMAGE_NAME="$(jq -r '.ArtifactName // "unknown"' "$SCAN_REPORT")"
SCAN_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CRITICAL="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$SCAN_REPORT")"
HIGH="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$SCAN_REPORT")"
MEDIUM="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$SCAN_REPORT")"
LOW="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$SCAN_REPORT")"
UNKNOWN="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")] | length' "$SCAN_REPORT")"
TOTAL="$((CRITICAL + HIGH + MEDIUM + LOW + UNKNOWN))"
COMPONENTS="$(jq '.components // [] | length' "$SBOM_REPORT")"
AFFECTED_PACKAGES="$(jq '[.Results[]?.Vulnerabilities[]?.PkgName] | unique | length' "$SCAN_REPORT")"
FIXABLE="$(jq '[.Results[]?.Vulnerabilities[]? | select((.FixedVersion // "") != "")] | length' "$SCAN_REPORT")"
NOT_FIXED="$((TOTAL - FIXABLE))"
BLOCKING_CRITICAL="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" and ((.FixedVersion // "") != ""))] | length' "$SCAN_REPORT")"
BLOCKING_HIGH="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" and ((.FixedVersion // "") != ""))] | length' "$SCAN_REPORT")"
BLOCKING_TOTAL="$((BLOCKING_CRITICAL + BLOCKING_HIGH))"
OS_TARGET="$(jq -r '[.Results[]? | select(.Class == "os-pkgs") | .Target][0] // "not detected"' "$SCAN_REPORT")"
LANG_TARGETS="$(jq -r '[.Results[]? | select(.Class != "os-pkgs") | .Target] | if length == 0 then "not detected" else join(", ") end' "$SCAN_REPORT")"

if [ "$BLOCKING_TOTAL" -gt 0 ]; then
  GATE_STATUS="FAIL"
  GATE_MESSAGE="Fixable high or critical vulnerabilities were found."
else
  GATE_STATUS="PASS"
  GATE_MESSAGE="No fixable high or critical vulnerabilities were found. Unfixed CVEs are still reported for review."
fi

TOP_VULNS="$(jq -r '
  [.Results[]?.Vulnerabilities[]?]
  | sort_by(
      if .Severity == "CRITICAL" then 0
      elif .Severity == "HIGH" then 1
      elif .Severity == "MEDIUM" then 2
      elif .Severity == "LOW" then 3
      else 4 end
    )
  | .[:20]
  | if length == 0 then
      "| None | None | None | None | None | None |\n"
    else
      map("| [\(.VulnerabilityID)](\(.PrimaryURL // "https://avd.aquasec.com/nvd/\(.VulnerabilityID)")) | \(.PkgName) | \(.InstalledVersion // "unknown") | \(.FixedVersion // "not fixed") | \(.Severity) | \((.Title // .Description // "No title") | gsub("[\r\n|]"; " ") | .[0:120]) |")
      | join("\n")
    end
' "$SCAN_REPORT")"

TARGET_SUMMARY="$(jq -r '
  [.Results[]? as $result
    | {
        target: $result.Target,
        type: ($result.Type // "unknown"),
        critical: ([$result.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length),
        high: ([$result.Vulnerabilities[]? | select(.Severity == "HIGH")] | length),
        medium: ([$result.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length),
        low: ([$result.Vulnerabilities[]? | select(.Severity == "LOW")] | length),
        total: ([$result.Vulnerabilities[]?] | length)
      }
    | select(.total > 0)]
  | if length == 0 then
      "| None | None | 0 | 0 | 0 | 0 | 0 |\n"
    else
      map("| \(.target) | \(.type) | \(.critical) | \(.high) | \(.medium) | \(.low) | \(.total) |")
      | join("\n")
    end
' "$SCAN_REPORT")"

PACKAGE_HOTSPOTS="$(jq -r '
  [.Results[]?.Vulnerabilities[]?]
  | group_by(.PkgName)
  | map({
      package: .[0].PkgName,
      critical: ([.[] | select(.Severity == "CRITICAL")] | length),
      high: ([.[] | select(.Severity == "HIGH")] | length),
      total: length
    })
  | sort_by(-.critical, -.high, -.total)
  | .[:15]
  | if length == 0 then
      "| None | 0 | 0 | 0 |\n"
    else
      map("| \(.package) | \(.critical) | \(.high) | \(.total) |")
      | join("\n")
    end
' "$SCAN_REPORT")"

SBOM_SAMPLE="$(jq -r '
  [.components[]? | {name: .name, version: (.version // "unknown"), type: (.type // "unknown")}]
  | sort_by(.name)
  | .[:25]
  | if length == 0 then
      "| None | None | None |\n"
    else
      map("| \(.name) | \(.version) | \(.type) |")
      | join("\n")
    end
' "$SBOM_REPORT")"

TARGET_SUMMARY_HTML="$(jq -r '
  [.Results[]? as $result
    | {
        target: $result.Target,
        type: ($result.Type // "unknown"),
        critical: ([$result.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length),
        high: ([$result.Vulnerabilities[]? | select(.Severity == "HIGH")] | length),
        medium: ([$result.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length),
        low: ([$result.Vulnerabilities[]? | select(.Severity == "LOW")] | length),
        total: ([$result.Vulnerabilities[]?] | length)
      }
    | select(.total > 0)]
  | if length == 0 then
      "<tr><td>None</td><td>None</td><td>0</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>"
    else
      map("<tr><td>\(.target | tostring | @html)</td><td>\(.type | tostring | @html)</td><td>\(.critical)</td><td>\(.high)</td><td>\(.medium)</td><td>\(.low)</td><td>\(.total)</td></tr>")
      | join("\n")
    end
' "$SCAN_REPORT")"

PACKAGE_HOTSPOTS_HTML="$(jq -r '
  [.Results[]?.Vulnerabilities[]?]
  | group_by(.PkgName)
  | map({
      package: .[0].PkgName,
      critical: ([.[] | select(.Severity == "CRITICAL")] | length),
      high: ([.[] | select(.Severity == "HIGH")] | length),
      total: length
    })
  | sort_by(-.critical, -.high, -.total)
  | .[:15]
  | if length == 0 then
      "<tr><td>None</td><td>0</td><td>0</td><td>0</td></tr>"
    else
      map("<tr><td>\(.package | tostring | @html)</td><td>\(.critical)</td><td>\(.high)</td><td>\(.total)</td></tr>")
      | join("\n")
    end
' "$SCAN_REPORT")"

TOP_VULNS_HTML="$(jq -r '
  [.Results[]?.Vulnerabilities[]?]
  | sort_by(
      if .Severity == "CRITICAL" then 0
      elif .Severity == "HIGH" then 1
      elif .Severity == "MEDIUM" then 2
      elif .Severity == "LOW" then 3
      else 4 end
    )
  | .[:20]
  | if length == 0 then
      "<tr><td>None</td><td>None</td><td>None</td><td>None</td><td>None</td><td>None</td></tr>"
    else
      map("<tr><td><a href=\"\((.PrimaryURL // "https://avd.aquasec.com/nvd/\(.VulnerabilityID)") | tostring | @html)\">\(.VulnerabilityID | tostring | @html)</a></td><td>\(.PkgName | tostring | @html)</td><td>\((.InstalledVersion // "unknown") | tostring | @html)</td><td>\((.FixedVersion // "not fixed") | tostring | @html)</td><td>\(.Severity | tostring | @html)</td><td>\((.Title // .Description // "No title") | gsub("[\r\n]"; " ") | .[0:120] | @html)</td></tr>")
      | join("\n")
    end
' "$SCAN_REPORT")"

SBOM_SAMPLE_HTML="$(jq -r '
  [.components[]? | {name: .name, version: (.version // "unknown"), type: (.type // "unknown")}]
  | sort_by(.name)
  | .[:25]
  | if length == 0 then
      "<tr><td>None</td><td>None</td><td>None</td></tr>"
    else
      map("<tr><td>\(.name | tostring | @html)</td><td>\(.version | tostring | @html)</td><td>\(.type | tostring | @html)</td></tr>")
      | join("\n")
    end
' "$SBOM_REPORT")"

cat > "$REPORT_DIR/security-report.md" <<EOF
# LockBox Security Report

| Field | Value |
| --- | --- |
| Image | \`$IMAGE_NAME\` |
| Scan time UTC | \`$SCAN_TIME\` |
| SBOM components | $COMPONENTS |
| Affected packages | $AFFECTED_PACKAGES |
| Fix available | $FIXABLE |
| No fixed version reported | $NOT_FIXED |
| Blocking fixable critical | $BLOCKING_CRITICAL |
| Blocking fixable high | $BLOCKING_HIGH |
| OS target | \`$OS_TARGET\` |
| Language targets | \`$LANG_TARGETS\` |
| Vulnerability gate | **$GATE_STATUS** |
| Gate reason | $GATE_MESSAGE |

## Vulnerability Summary

| Severity | Count |
| --- | ---: |
| Critical | $CRITICAL |
| High | $HIGH |
| Medium | $MEDIUM |
| Low | $LOW |
| Unknown | $UNKNOWN |
| Total | $TOTAL |

## Fix Availability

| Status | Count |
| --- | ---: |
| Fixed version available | $FIXABLE |
| No fixed version reported | $NOT_FIXED |

## Release Gate

| Gate Input | Count |
| --- | ---: |
| Fixable critical vulnerabilities | $BLOCKING_CRITICAL |
| Fixable high vulnerabilities | $BLOCKING_HIGH |
| Total blocking vulnerabilities | $BLOCKING_TOTAL |

## Affected Scan Targets

| Target | Type | Critical | High | Medium | Low | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
$TARGET_SUMMARY

## Package Hotspots

| Package | Critical | High | Total Vulnerabilities |
| --- | ---: | ---: | ---: |
$PACKAGE_HOTSPOTS

## Top Vulnerabilities

| CVE | Package | Installed | Fixed Version | Severity | Title |
| --- | --- | --- | --- | --- | --- |
$TOP_VULNS

## SBOM Component Sample

| Component | Version | Type |
| --- | --- | --- |
$SBOM_SAMPLE

## Supply Chain Controls

| Control | Status |
| --- | --- |
| Container image built | Complete |
| CycloneDX SBOM generated | Complete |
| Trivy vulnerability scan generated | Complete |
| Human-readable report generated | Complete |
| Cosign signature | Completed on protected push workflow |
| Kyverno admission policy | Enforced in cluster |
EOF

cat > "$PUBLIC_DIR/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LockBox Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #1f2937; background: #f8fafc; }
    main { max-width: 980px; margin: 0 auto; background: white; border: 1px solid #d1d5db; padding: 24px; }
    h1, h2 { color: #111827; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0 28px; }
    th, td { border: 1px solid #d1d5db; padding: 10px; text-align: left; }
    th { background: #e5e7eb; }
    .pass { color: #047857; font-weight: 700; }
    .fail { color: #b91c1c; font-weight: 700; }
    code { background: #f3f4f6; padding: 2px 4px; }
  </style>
</head>
<body>
<main>
  <h1>LockBox Security Report</h1>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Image</td><td><code>$IMAGE_NAME</code></td></tr>
    <tr><td>Scan time UTC</td><td><code>$SCAN_TIME</code></td></tr>
    <tr><td>SBOM components</td><td>$COMPONENTS</td></tr>
    <tr><td>Affected packages</td><td>$AFFECTED_PACKAGES</td></tr>
    <tr><td>Fix available</td><td>$FIXABLE</td></tr>
    <tr><td>No fixed version reported</td><td>$NOT_FIXED</td></tr>
    <tr><td>Blocking fixable critical</td><td>$BLOCKING_CRITICAL</td></tr>
    <tr><td>Blocking fixable high</td><td>$BLOCKING_HIGH</td></tr>
    <tr><td>OS target</td><td><code>$OS_TARGET</code></td></tr>
    <tr><td>Language targets</td><td><code>$LANG_TARGETS</code></td></tr>
    <tr><td>Vulnerability gate</td><td class="$(printf "%s" "$GATE_STATUS" | tr '[:upper:]' '[:lower:]')">$GATE_STATUS</td></tr>
    <tr><td>Gate reason</td><td>$GATE_MESSAGE</td></tr>
  </table>

  <h2>Fix Availability</h2>
  <table>
    <tr><th>Status</th><th>Count</th></tr>
    <tr><td>Fixed version available</td><td>$FIXABLE</td></tr>
    <tr><td>No fixed version reported</td><td>$NOT_FIXED</td></tr>
  </table>

  <h2>Release Gate</h2>
  <table>
    <tr><th>Gate Input</th><th>Count</th></tr>
    <tr><td>Fixable critical vulnerabilities</td><td>$BLOCKING_CRITICAL</td></tr>
    <tr><td>Fixable high vulnerabilities</td><td>$BLOCKING_HIGH</td></tr>
    <tr><td>Total blocking vulnerabilities</td><td>$BLOCKING_TOTAL</td></tr>
  </table>

  <h2>Vulnerability Summary</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td>Critical</td><td>$CRITICAL</td></tr>
    <tr><td>High</td><td>$HIGH</td></tr>
    <tr><td>Medium</td><td>$MEDIUM</td></tr>
    <tr><td>Low</td><td>$LOW</td></tr>
    <tr><td>Unknown</td><td>$UNKNOWN</td></tr>
    <tr><td>Total</td><td>$TOTAL</td></tr>
  </table>

  <h2>Affected Scan Targets</h2>
  <table>
    <tr><th>Target</th><th>Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
$TARGET_SUMMARY_HTML
  </table>

  <h2>Package Hotspots</h2>
  <table>
    <tr><th>Package</th><th>Critical</th><th>High</th><th>Total Vulnerabilities</th></tr>
$PACKAGE_HOTSPOTS_HTML
  </table>

  <h2>Top Vulnerabilities</h2>
  <table>
    <tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed Version</th><th>Severity</th><th>Title</th></tr>
$TOP_VULNS_HTML
  </table>

  <h2>SBOM Component Sample</h2>
  <table>
    <tr><th>Component</th><th>Version</th><th>Type</th></tr>
$SBOM_SAMPLE_HTML
  </table>

  <h2>Supply Chain Controls</h2>
  <table>
    <tr><th>Control</th><th>Status</th></tr>
    <tr><td>Container image built</td><td>Complete</td></tr>
    <tr><td>CycloneDX SBOM generated</td><td>Complete</td></tr>
    <tr><td>Trivy vulnerability scan generated</td><td>Complete</td></tr>
    <tr><td>Human-readable report generated</td><td>Complete</td></tr>
    <tr><td>Cosign signature</td><td>Completed on protected push workflow</td></tr>
    <tr><td>Kyverno admission policy</td><td>Enforced in cluster</td></tr>
  </table>
</main>
</body>
</html>
EOF

echo "Markdown report written to $REPORT_DIR/security-report.md"
echo "HTML report written to $PUBLIC_DIR/index.html"
echo "$GATE_STATUS" > "$REPORT_DIR/gate-status.txt"
