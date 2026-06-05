#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-lockbox:v1}"
OUTPUT="${2:-artifacts/scan-report.json}"
SBOM_OUTPUT="${3:-artifacts/sbom.json}"

mkdir -p "$(dirname "$OUTPUT")"

if [ ! -f "$SBOM_OUTPUT" ]; then
  trivy image \
    --format cyclonedx \
    --output "$SBOM_OUTPUT" \
    "$IMAGE"
fi

trivy image \
  --format json \
  --output "$OUTPUT" \
  "$IMAGE"

scripts/render-report.sh "$OUTPUT" "$SBOM_OUTPUT" reports public

trivy image \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  "$IMAGE"

echo "Scan report written to $OUTPUT"
