#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: scripts/sign-image.sh ghcr.io/gajapriyanagulraj/lockbox:<tag>}"

cosign sign --yes "$IMAGE"
cosign verify \
  --certificate-identity-regexp "https://github.com/.+/.github/workflows/.+@refs/heads/.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$IMAGE"
