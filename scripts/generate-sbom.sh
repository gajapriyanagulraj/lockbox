#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-lockbox:v1}"
OUTPUT="${2:-artifacts/sbom.json}"

mkdir -p "$(dirname "$OUTPUT")"

trivy image \
  --format cyclonedx \
  --output "$OUTPUT" \
  "$IMAGE"

echo "SBOM written to $OUTPUT"
