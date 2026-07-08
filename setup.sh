#!/usr/bin/env bash
# Clone the two dependency repositories the toolkit builds against, pinned to the
# exact commit the challenge used, into ./vendor.
set -euo pipefail

VENDOR="$(cd "$(dirname "$0")" && pwd)/vendor"
mkdir -p "$VENDOR"

PVAC_COMMIT="e2835df34ebbc510d3f8c93062dc5bf5bc34d2dc"   # pinned in the challenge manifest

if [ ! -d "$VENDOR/pvac_hfhe_cpp/.git" ]; then
  git clone https://github.com/octra-labs/pvac_hfhe_cpp.git "$VENDOR/pvac_hfhe_cpp"
fi
git -C "$VENDOR/pvac_hfhe_cpp" checkout "$PVAC_COMMIT"

if [ ! -d "$VENDOR/hfhe-challenge/.git" ]; then
  git clone https://github.com/octra-labs/hfhe-challenge.git "$VENDOR/hfhe-challenge"
fi

echo
echo "Dependencies ready in $VENDOR"
echo "Now run:  make"
echo "Then:     ./bin/parse_artifacts vendor/hfhe-challenge"
