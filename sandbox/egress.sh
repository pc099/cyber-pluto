#!/usr/bin/env bash
#
# egress.sh — the AUTHORITATIVE scope control (board-ratified v0).
#
# Applies an nftables owner-match egress allowlist for the unprivileged `pluto`
# uid: default-DROP everything `pluto` emits EXCEPT the operator's in-scope
# target hosts, the LLM provider endpoint(s), loopback, and DNS to one resolver.
# Because it matches `meta skuid pluto` in ROOT's ruleset, (a) it never touches
# root/operator/VPN traffic, (b) the agent has no CAP_NET_ADMIN to flush it, and
# (c) it is inherited by every child tool and sub-agent automatically. It is
# applied by the ROOT launcher BEFORE the agent starts, from OPERATOR scope only
# — the agent cannot widen it (DB scope_notes / /etc/hosts are irrelevant at L3).
#
# Usage:
#   sudo sandbox/egress.sh apply "10.129.0.0/16 192.168.122.0/24" [provider_host...]
#   sudo sandbox/egress.sh teardown
#   sudo sandbox/egress.sh show
#
# Env: PLUTO_UID (default pluto), PLUTO_RESOLVER (default: first nameserver in
# /etc/resolv.conf), PLUTO_PROVIDER_HOSTS (space list, resolved + pinned).
set -euo pipefail

TABLE="inet pluto_egress"
UIDNAME="${PLUTO_UID:-pluto}"

resolver() {
	if [[ -n "${PLUTO_RESOLVER:-}" ]]; then echo "$PLUTO_RESOLVER"; return; fi
	awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || echo "127.0.0.1"
}

resolve_ips() { # host -> its A records, one per line
	getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u
}

cmd_teardown() { nft delete table inet pluto_egress 2>/dev/null || true; echo "egress: pluto allowlist removed"; }

cmd_apply() {
	local scope="$1"; shift || true
	local providers=("$@")
	id "$UIDNAME" >/dev/null 2>&1 || { echo "user '$UIDNAME' does not exist (run sandbox/setup-user.sh)" >&2; exit 1; }
	local res; res="$(resolver)"

	# Build the allowed destination set: scope hosts/CIDRs + resolved provider IPs.
	local -a allowed=()
	for h in $scope; do allowed+=("$h"); done
	for p in "${providers[@]:-}"; do
		[[ -z "$p" ]] && continue
		while read -r ip; do [[ -n "$ip" ]] && allowed+=("$ip"); done < <(resolve_ips "$p")
	done
	[[ ${#allowed[@]} -eq 0 ]] && { echo "refusing to apply an empty allowlist (no scope)" >&2; exit 1; }
	local set_elems; set_elems="$(printf '%s, ' "${allowed[@]}")"; set_elems="${set_elems%, }"

	cmd_teardown
	nft -f - <<NFT
table inet pluto_egress {
  set allowed {
    type ipv4_addr
    flags interval
    elements = { ${set_elems} }
  }
  chain out {
    type filter hook output priority 0; policy accept;
    # Only govern uid ${UIDNAME}; all other users (root, operator, VPN) untouched.
    meta skuid != ${UIDNAME} accept
    oif lo accept
    ip daddr @allowed accept
    ip daddr ${res} udp dport 53 accept
    ip daddr ${res} tcp dport 53 accept
    # Anything else this uid emits is dropped (authoritative default-DROP).
    counter drop
  }
}
NFT
	echo "egress: pluto allowlist applied — scope+provider hosts allowed, resolver ${res}, all else DROP"
	echo "  allowed: ${set_elems}"
}

case "${1:-}" in
	apply)    shift; cmd_apply "$@" ;;
	teardown) cmd_teardown ;;
	show)     nft list table inet pluto_egress 2>/dev/null || echo "(no pluto egress table)" ;;
	*) echo "usage: $0 {apply \"<scope hosts/CIDRs>\" [provider_host...] | teardown | show}" >&2; exit 1 ;;
esac
