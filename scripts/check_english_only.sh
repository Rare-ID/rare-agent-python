#!/usr/bin/env bash
set -euo pipefail
TARGETS=(README.md CONTRIBUTING.md SECURITY.md SUPPORT.md CODE_OF_CONDUCT.md .github)
if rg -n "[\x{4E00}-\x{9FFF}]" "${TARGETS[@]}"; then
  echo "Non-English (CJK) text detected in public-facing files." >&2
  exit 1
fi
echo "English-only check passed."
