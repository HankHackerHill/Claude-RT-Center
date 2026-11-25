#!/usr/bin/env bash
# Host-side isolation for br-range. Idempotent; needs root (uses sudo when not root). Run by bootstrap.sh after the
# range is up, and again after every reboot or range network re-creation (per-interface sysctls reset with the bridge).
#
# Why: `internal: true` + inhibit_ipv4 stop ROUTED traffic, but a range container with CAP_NET_RAW (the attacker box
# needs it for nmap -sS) can send raw Ethernet frames to the bridge's MAC addressed to any host-local IP. With
# rp_filter=0 and an empty INPUT chain the host processes them (observed: 3/3 injected ICMP echoes answered) - a path
# to host services and, via spoofed sources, a reflection/exfil channel. These rules close it at the host:
#   - rp_filter=1 on br-range: with no address on the bridge, every routed packet from it fails validation
#   - INPUT drop for anything arriving on br-range (the host never needs to talk to the range at L3)
#   - IPv6: disabled on br-range + ip6tables INPUT drop (when the kernel has IPv6)
# Deliberately NOT a raw/PREROUTING drop: with bridge-nf-call-iptables=1 that runs before frames reach br-range's
# packet taps, so it also blinded Suricata to the attempt (observed). rp_filter + INPUT act after capture: the
# attempt is still blocked (observed: 0 echoes processed) AND detected (tripwires 9000007/9000009).
# Intra-range traffic is bridged at L2 and unaffected. scripts/verify.py checks every item and probes it (l2_probe.py).
set -euo pipefail
BR=br-range
RANGE_CIDR=172.30.0.0/24
TAG="cc-range-isolation"
SUDO=(); [[ $EUID -eq 0 ]] || SUDO=(sudo)

[[ -d /sys/class/net/$BR ]] || { echo "[harden] $BR does not exist: start the range first" >&2; exit 1; }

ensure() {  # ensure <cmd> <table> <chain> <rule...>: insert at the top unless already present
  local cmd=$1 table=$2 chain=$3; shift 3
  if ! "${SUDO[@]}" "$cmd" -t "$table" -C "$chain" "$@" 2>/dev/null; then
    "${SUDO[@]}" "$cmd" -t "$table" -I "$chain" 1 "$@"
    echo "[harden] $cmd -t $table -I $chain $*"
  fi
}

ensure iptables filter INPUT -i "$BR" -m comment --comment "$TAG" -j DROP
# remove the earlier v4 raw rule if a host still has it (see above)
"${SUDO[@]}" iptables -t raw -D PREROUTING -i "$BR" ! -d "$RANGE_CIDR" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
"${SUDO[@]}" sysctl -q -w "net.ipv4.conf.$BR.rp_filter=1"
if [[ -d /proc/sys/net/ipv6/conf/$BR ]]; then
  "${SUDO[@]}" sysctl -q -w "net.ipv6.conf.$BR.disable_ipv6=1"
  command -v ip6tables >/dev/null && ensure ip6tables filter INPUT -i "$BR" -m comment --comment "$TAG" -j DROP
fi
echo "[harden] $BR: rp_filter=1, INPUT drop, IPv6 off (if present)"
