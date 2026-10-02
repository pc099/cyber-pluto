#!/usr/bin/env bash
# Explicit offline deployment; never binds or freezes the development checkout.
# Usage: sudo sandbox/setup.sh [ABSENT-RUNTIME-PATH]
set -euo pipefail
fail() { echo "setup refused: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "root required"
# Launcher and resume descriptors use these canonical resources. Refuse stale
# overrides before creating directories, identities, keys or deployment stages.
for setting in PLUTO_UID PLUTO_RUN_DIR PLUTO_CONTROL_DIR PLUTO_ENGAGEMENTS_DIR PLUTO_KEYDIR; do
 case "$setting" in
  PLUTO_UID) expected=pluto ;;
  PLUTO_RUN_DIR) expected=/run/cyber-pluto ;;
  PLUTO_CONTROL_DIR) expected=/var/lib/cyber-pluto/control ;;
  PLUTO_ENGAGEMENTS_DIR) expected=/var/lib/cyber-pluto/engagements ;;
  PLUTO_KEYDIR) expected=/etc/cyber-pluto ;;
 esac
 [[ ! -v "$setting" || "${!setting}" == "$expected" ]] || fail "$setting must be $expected for the canonical launcher"
done
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEPLOY="${1:-/opt/cyber-pluto}"
UIDNAME=pluto
for program in node bwrap setpriv flock openssl; do command -v "$program" >/dev/null || fail "missing prerequisite: $program (install separately)"; done
[[ -f "$SRC/extensions/dist/launcher/deploy.js" ]] || fail "build extensions before deployment"
[[ ! -e "$DEPLOY" && ! -L "$DEPLOY" ]] || fail "destination exists; select an absent versioned runtime path"

root_dir() {
 local path="$1" parent mode
 [[ "$path" == /* && "$path" != /root && "$path" != /root/* ]] || fail "root resource path must be absolute and outside /root"
 parent="$(dirname "$path")"
 if [[ "$path" != / ]]; then root_dir "$parent"; fi
 [[ ! -L "$path" ]] || fail "symlink directory: $path"
 mkdir -p -m 0755 -- "$path"
 [[ "$(realpath -e "$path")" == "$path" && "$(stat -c %u "$path")" == 0 ]] || fail "unsafe root directory: $path"
 mode="$(stat -c %a "$path")"
 (( (8#$mode & 0022) == 0 )) || fail "writable root directory: $path"
 (( (8#$mode & 0055) == 0055 )) || fail "root directory not traversable: $path"
}
RUN_DIR=/run/cyber-pluto
CONTROL_DIR=/var/lib/cyber-pluto/control
ENGAGEMENTS_DIR=/var/lib/cyber-pluto/engagements
KEYDIR=/etc/cyber-pluto
root_dir "$RUN_DIR"; root_dir "$RUN_DIR/signers"; root_dir "$CONTROL_DIR"; root_dir "$ENGAGEMENTS_DIR"; root_dir "$KEYDIR"
[[ ! -L "$RUN_DIR/setup.lock" ]] || fail "symlink setup lock"
exec 9>"$RUN_DIR/setup.lock"; flock -n 9 || fail "another setup is active"
id "$UIDNAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$UIDNAME"
[[ "$(id -u "$UIDNAME")" != 0 ]] || fail "agent uid must be unprivileged"

PRIV="$KEYDIR/promotion_ed25519.key"; PUB="$KEYDIR/promotion_ed25519.pub"
if [[ ! -e "$PRIV" && ! -L "$PRIV" && ! -e "$PUB" && ! -L "$PUB" ]]; then
 KEY_STAGE="$(mktemp -d "$KEYDIR/.keypair.XXXXXXXX")"
 trap 'rm -f -- "$KEY_STAGE/private.key" "$KEY_STAGE/public.pub"; rmdir "$KEY_STAGE"' EXIT
 openssl genpkey -algorithm ed25519 -out "$KEY_STAGE/private.key"
 openssl pkey -in "$KEY_STAGE/private.key" -pubout -out "$KEY_STAGE/public.pub"
 chmod 0400 "$KEY_STAGE/private.key"; chmod 0444 "$KEY_STAGE/public.pub"
 mv "$KEY_STAGE/private.key" "$PRIV"; mv "$KEY_STAGE/public.pub" "$PUB"
 rmdir "$KEY_STAGE"; trap - EXIT
fi
[[ -f "$PRIV" && ! -L "$PRIV" && -f "$PUB" && ! -L "$PUB" ]] || fail "incomplete or symlink keypair; repair explicitly"
[[ "$(stat -c '%u:%a' "$PRIV")" == 0:400 && "$(stat -c '%u:%a' "$PUB")" == 0:444 ]] || fail "keypair ownership/modes must be root:0400 and root:0444"
openssl pkey -in "$PRIV" -pubout | cmp -s - "$PUB" || fail "keypair mismatch"

node "$SRC/extensions/dist/launcher/deploy.js" "$SRC" "$DEPLOY"
echo "Runtime deployed: $DEPLOY"
echo "Workspace base: $ENGAGEMENTS_DIR; operator control: $CONTROL_DIR/KILL_SWITCH"
echo "Run the no-model sandbox readiness check before any target engagement."
