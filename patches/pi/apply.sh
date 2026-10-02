#!/usr/bin/env bash
# Apply the tracked local Pi delta without changing the submodule commit.
set -euo pipefail
patch_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pi_dir="${1:-$patch_dir/../../pi/pi}"
pending=()
for patch_file in "$patch_dir/abort-continuation.patch" "$patch_dir/settings-readonly.patch"; do
 if git -C "$pi_dir" apply --reverse --check "$patch_file" 2>/dev/null; then
  echo "Pi patch already applied: $(basename "$patch_file")"
 else
  git -C "$pi_dir" apply --check "$patch_file"
  pending+=("$patch_file")
 fi
done
# Verify every delta before making changes; refuse incompatible partial trees.
for patch_file in "${pending[@]}"; do
 git -C "$pi_dir" apply "$patch_file"
 echo "Pi patch applied: $(basename "$patch_file")"
done
echo "Rebuild coding-agent SDK and CLI before running Pluto."
