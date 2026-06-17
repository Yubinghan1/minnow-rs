#!/usr/bin/env bash
set -euo pipefail

DEV="${DEV:-tap144}"
HOST_IP="${HOST_IP:-169.254.144.1}"
STACK_IP="${STACK_IP:-169.254.144.2}"
HOST_MAC="${HOST_MAC:-02:00:00:00:00:01}"
STACK_MAC="${STACK_MAC:-02:00:00:00:00:02}"
LOCAL_PORT="${LOCAL_PORT:-50000}"
PEER_PORT="${PEER_PORT:-9090}"
PCAP="${PCAP:-target/minnow-captures/tap-host.pcap}"
MTU="${MTU:-1500}"

usage() {
  cat <<EOF
Usage:
  $0 setup
  $0 run
  $0 ping
  $0 listen
  $0 clean

Environment:
  DEV=$DEV
  HOST_IP=$HOST_IP
  STACK_IP=$STACK_IP
  HOST_MAC=$HOST_MAC
  STACK_MAC=$STACK_MAC
  LOCAL_PORT=$LOCAL_PORT
  PEER_PORT=$PEER_PORT
  PCAP=$PCAP

Notes:
  TAP is a Layer 2 demo: the pcap contains Ethernet, ARP, IPv4, ICMP, and TCP.
EOF
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "TUN/TAP demos require Linux." >&2
    exit 1
  fi
}

setup() {
  require_linux
  sudo ip tuntap add dev "$DEV" mode tap user "$(id -un)" 2>/dev/null || true
  sudo ip link set dev "$DEV" address "$HOST_MAC"
  sudo ip addr replace "$HOST_IP/24" dev "$DEV"
  sudo ip link set dev "$DEV" mtu "$MTU" up
  sudo ip route replace "$STACK_IP/32" dev "$DEV"
  mkdir -p "$(dirname "$PCAP")"

  echo "TAP device is ready:"
  echo "  kernel side : $DEV $HOST_IP/24 $HOST_MAC"
  echo "  minnow-rs   : $STACK_IP $STACK_MAC"
}

run_host() {
  setup
  exec cargo run --bin tap_host -- \
    --tap "$DEV" \
    --local-mac "$STACK_MAC" \
    --local-ip "$STACK_IP" \
    --peer-ip "$HOST_IP" \
    --local-port "$LOCAL_PORT" \
    --peer-port "$PEER_PORT" \
    --pcap "$PCAP"
}

ping_stack() {
  require_linux
  ping -c 4 "$STACK_IP"
}

listen_peer() {
  require_linux
  echo "Listening on $HOST_IP:$PEER_PORT for the TCP demo."
  exec nc -l "$HOST_IP" "$PEER_PORT"
}

clean() {
  require_linux
  sudo ip link del "$DEV" 2>/dev/null || true
}

case "${1:-}" in
  setup) setup ;;
  run) run_host ;;
  ping) ping_stack ;;
  listen) listen_peer ;;
  clean) clean ;;
  -h|--help|help|"") usage ;;
  *)
    echo "unknown command: $1" >&2
    usage
    exit 1
    ;;
esac
