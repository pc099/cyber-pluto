#!/usr/bin/env bash
# Apply the tracked local Pi delta without changing the submodule commit.
set -euo pipefail
patch_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pi_dir="${1:-$patch_dir/../../pi/pi}"
patch_file="$patch_dir/abort-continuation.patch"
if git -C "$pi_dir" apply --reverse --check "$patch_file" 2>/dev/null; then
  echo "Pi cancellation patch is already applied."
  exit 0
fi
git -C "$pi_dir" apply --check "$patch_file"
git -C "$pi_dir" apply "$patch_file"
echo "Pi cancellation patch applied. Rebuild coding-agent before running Pluto."
