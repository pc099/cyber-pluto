#!/usr/bin/env bash
# Root launcher has already applied scope egress and prepared owned resources.
# This wrapper has no unconstrained fallback or filesystem provisioning.
set -euo pipefail
fail() { echo "sandbox refused: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "root launcher required"
[[ "${PLUTO_BWRAP:-1}" == 1 ]] || fail "bubblewrap must be enabled"
command -v bwrap >/dev/null || fail "bubblewrap missing"

UIDNAME="${PLUTO_UID:-pluto}"
PLUTO_UID_NUMBER="$(id -u "$UIDNAME")" || fail "dedicated uid missing"
PLUTO_GID_NUMBER="$(id -g "$UIDNAME")"
[[ "$PLUTO_UID_NUMBER" != 0 ]] || fail "agent uid must be unprivileged"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ "$REPO" != /root && "$REPO" != /root/* ]] || fail "runtime must be outside /root"
ENG_DIR="${1:?usage: run-sandboxed.sh <engagement_dir> -- <command...>}"; shift
[[ "${1:-}" == -- ]] && shift
[[ $# -gt 0 ]] || fail "command missing"
RUN_DIR="${PLUTO_RUN_DIR:-/run/cyber-pluto}"
CONTROL_DIR="${PLUTO_CONTROL_DIR:-/var/lib/cyber-pluto/control}"

# Sticky root-owned ancestors (e.g. /tmp for QA fixtures) protect named children.
# Each supplied leaf must itself be canonical and have the required ownership.
protected_parents() {
 local current="$1" mode owner
 while [[ "$current" != / ]]; do
  [[ -d "$current" && ! -L "$current" ]] || fail "unsafe directory: $current"
  owner="$(stat -c %u "$current")"; mode="$(stat -c %a "$current")"
  [[ "$owner" == 0 ]] || fail "ancestor not root-owned: $current"
  (( (8#$mode & 0022) == 0 || (8#$mode & 01000) != 0 )) || fail "writable ancestor: $current"
  (( (8#$mode & 0055) == 0055 )) || fail "ancestor not traversable: $current"
  current="$(dirname "$current")"
 done
}
root_leaf() {
 local path="$1" mode
 [[ "$path" == /* && "$(realpath -e "$path")" == "$path" ]] || fail "noncanonical path: $path"
 protected_parents "$path"
 mode="$(stat -c %a "$path")"
 (( (8#$mode & 0022) == 0 )) || fail "root directory is writable: $path"
}
root_leaf "$REPO"; root_leaf "$RUN_DIR"; root_leaf "$CONTROL_DIR"
[[ "$ENG_DIR" == /* && "$(realpath -e "$ENG_DIR")" == "$ENG_DIR" && -d "$ENG_DIR" && ! -L "$ENG_DIR" ]] || fail "noncanonical workspace"
[[ "$ENG_DIR" != /root/* && "$ENG_DIR" != "$REPO" && "$ENG_DIR" != "$REPO"/* && "$ENG_DIR" != / && "$ENG_DIR" != "$RUN_DIR"* && "$ENG_DIR" != "$CONTROL_DIR"* ]] || fail "unsafe workspace location"
protected_parents "$(dirname "$ENG_DIR")"
[[ "$(stat -c %u "$ENG_DIR")" == "$PLUTO_UID_NUMBER" && "$(stat -c %g "$ENG_DIR")" == "$PLUTO_GID_NUMBER" ]] || fail "workspace ownership mismatch"
ENG_MODE="$(stat -c %a "$ENG_DIR")"
(( (8#$ENG_MODE & 0007) == 0 && (8#$ENG_MODE & 0700) == 0700 )) || fail "workspace permissions mismatch"
[[ -n "${PI_CODING_AGENT_DIR:-}" && "$PI_CODING_AGENT_DIR" == "$ENG_DIR"/* ]] || fail "agent config directory must be inside workspace"
[[ -d "$PI_CODING_AGENT_DIR" && ! -L "$PI_CODING_AGENT_DIR" && "$(realpath -e "$PI_CODING_AGENT_DIR")" == "$PI_CODING_AGENT_DIR" && "$(stat -c %u "$PI_CODING_AGENT_DIR")" == "$PLUTO_UID_NUMBER" ]] || fail "agent config directory must be prepared and canonical"
[[ -n "${PLUTO_PROMOTION_SIGNER_CMD:-}" && -n "${PLUTO_PROMOTION_PUBKEY:-}" ]] || fail "signing and verifying configuration required"

# No host init files, shared temporary storage, NODE_OPTIONS, or private-key config.
CHILD_ENV=(env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/nonexistent TERM="${TERM:-xterm}" BASH_ENV= ENV=)
while IFS='=' read -r key _; do
 case "$key" in
  PLUTO_PROMOTION_PRIVKEY|PLUTO_KEYDIR|PLUTO_SIGNER_STRICT) ;;
  PLUTO_*|PI_CODING_AGENT_DIR|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|DEEPSEEK_API_KEY|ZAI_API_KEY|GROQ_API_KEY|SHODAN_API_KEY) CHILD_ENV+=("$key=${!key}");;
 esac
done < <(env)

exec setpriv --no-new-privs --reuid "$UIDNAME" --regid "$UIDNAME" --init-groups -- \
 bwrap --ro-bind / / --dev /dev --proc /proc \
 --tmpfs /root --tmpfs /tmp --tmpfs /run \
 --ro-bind "$REPO" "$REPO" \
 --ro-bind "$RUN_DIR" "$RUN_DIR" --ro-bind "$CONTROL_DIR" "$CONTROL_DIR" \
 --bind "$ENG_DIR" "$ENG_DIR" \
 --die-with-parent --unshare-ipc --unshare-uts --chdir "$REPO" \
 "${CHILD_ENV[@]}" "$@"
