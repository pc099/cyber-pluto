#!/usr/bin/env bash
#
# setup.sh — one-time operator setup for the sandboxed harness (board v0).
#
# Prepares the host so `cyberpluto --sandbox` can run the agent as the confined
# `pluto` uid against a frozen, read-only harness tree. Run as root, once.
#
#   sudo sandbox/setup.sh [/opt/cyber-pluto]
#
# It: (1) creates the dedicated unprivileged `pluto` uid, (2) deploys the harness
# to a pluto-TRAVERSABLE path (NOT under /root, which is 0700 and blocks pluto
# from reading the tree at all) via a bind mount, (3) freezes the tree
# root-owned + world-read-only so the agent cannot modify the harness/gate, and
# (4) makes the engagements/ workspace pluto-writable.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="${1:-/opt/cyber-pluto}"
UIDNAME="${PLUTO_UID:-pluto}"

echo "[*] dedicated unprivileged uid '$UIDNAME'"
id "$UIDNAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$UIDNAME"

echo "[*] deploy harness to a pluto-traversable path: $DEPLOY (bind of $SRC)"
mkdir -p "$DEPLOY"; chmod 755 "$(dirname "$DEPLOY")" "$DEPLOY"
mountpoint -q "$DEPLOY" || mount --bind "$SRC" "$DEPLOY"

echo "[*] freeze the harness tree read-only to the agent (root-owned, o-w stripped)"
# NB: leaves the engagements/ workspace writable to pluto below. Build artifacts
# (extensions/dist, the Pi bundle) MUST be built by root BEFORE this step — the
# agent runs a frozen tree and cannot build.
chown -R root:root "$DEPLOY"
chmod -R o-w,g-w "$DEPLOY"
find "$DEPLOY" -type d -exec chmod o+rx,g+rx {} +   # pluto can read + traverse

echo "[*] pluto-writable workspace: $DEPLOY/engagements"
mkdir -p "$DEPLOY/engagements"; chown "$UIDNAME":"$UIDNAME" "$DEPLOY/engagements"; chmod 0770 "$DEPLOY/engagements"

echo "[*] Gate-1 promotion signing keypair (Item 0)"
# The PRIVATE key lives OUTSIDE the pluto-readable tree and is root-only (0400),
# so the confined agent can never read it — it can only ask the root signing
# daemon (started by the launcher) to sign, over a unix socket. The PUBLIC key is
# world-readable so consumers can verify. Verified on the box: pluto gets
# "Permission denied" on the private key but CAN sign through the socket under
# no_new_privs (sudo is unavailable there — setuid is disabled).
KEYDIR="${PLUTO_KEYDIR:-/etc/cyber-pluto}"
PRIV="$KEYDIR/promotion_ed25519.key"
PUB="$KEYDIR/promotion_ed25519.pub"
mkdir -p "$KEYDIR"; chmod 0755 "$KEYDIR"   # traversable, but the key itself is 0400
if [[ -f "$PRIV" ]]; then
	echo "    keypair already present at $PRIV (leaving it; delete to rotate)"
else
	command -v openssl >/dev/null || { echo "openssl not found; cannot generate the signing key" >&2; exit 1; }
	openssl genpkey -algorithm ed25519 -out "$PRIV"
	openssl pkey -in "$PRIV" -pubout -out "$PUB"
	chown root:root "$PRIV" "$PUB"; chmod 0400 "$PRIV"; chmod 0444 "$PUB"
	echo "    private (root-only 0400): $PRIV"
	echo "    public  (world-read 0444): $PUB"
fi
# The launcher reads the private key from PROMOTION_PRIVKEY_DEFAULT
# (/etc/cyber-pluto/promotion_ed25519.key) unless PLUTO_PROMOTION_PRIVKEY is set.
[[ "$PRIV" == "/etc/cyber-pluto/promotion_ed25519.key" ]] || \
	echo "    NOTE: non-default key path — export PLUTO_PROMOTION_PRIVKEY=$PRIV when launching."

echo
echo "  ✅ setup complete."
echo "  Run a sandboxed engagement (as root — it drops to $UIDNAME):"
echo "     cd $DEPLOY && ./cyberpluto <target> --sandbox --headless"
echo "  The kill switch stays root-owned: touch $DEPLOY/state/KILL_SWITCH to halt."
echo "  Rebuild after a code change: (as root) cd $DEPLOY/extensions && npm run build,"
echo "  then re-run this script to re-freeze."

echo "[*] SecLists web-content wordlists (Decision 0006 — real content discovery)"
SLDIR=/usr/share/seclists/Discovery/Web-Content
mkdir -p "$SLDIR"
for w in raft-large-directories.txt raft-large-files.txt; do
  [ -s "$SLDIR/$w" ] || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$w" -o "$SLDIR/$w" && echo "    $w ready" || echo "    WARN: could not fetch $w"
done
