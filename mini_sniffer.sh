set -u

NONE='\033[0m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'

info(){ echo -e "${CYAN}[INFO]${NONE} $*"; }
ok(){ echo -e "${GREEN}[OK]${NONE} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NONE} $*"; }
err(){ echo -e "${RED}[ERROR]${NONE} $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "This script requires root. Run with sudo."
  exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  err "tcpdump not found. Install tcpdump and run again."
  exit 1
fi

IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
SRCIP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
if [ -z "$IFACE" ]; then
  warn "Couldn't auto-detect interface. Using 'any'."
  IFACE="any"
fi
info "Mini sniffer — capturing on: $IFACE"

NETCIDR=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')
if [ -z "$NETCIDR" ]; then
  warn "Couldn't detect IPv4 CIDR for $IFACE — falling back to /24."
  if [ -n "$SRCIP" ]; then
    NET="${SRCIP%.*}.0/24"
  else
    NET="192.168.1.0/24"
  fi
else
  NET="$NETCIDR"
fi
info "Using network: $NET (ping sweep to populate ARP table)"


BASE_IP=$(echo "$NET" | cut -d'/' -f1)
NETBASE="${BASE_IP%.*}"

info "Performing short ping sweep (this may take a few seconds)..."
for i in $(seq 1 254); do
  ip="$NETBASE.$i"
  if [ "$ip" = "$SRCIP" ]; then continue; fi
  ping -c1 -W1 -n "$ip" > /dev/null 2>&1 &
  while [ "$(jobs -rp | wc -l)" -gt 200 ]; do sleep 0.05; done
done
wait

info "Found devices on network:"
printf "  %-15s %-18s %s\n" "IP" "Hostname" "MAC"
DEVICE_COUNT=0
ip -4 neigh show dev "$IFACE" | awk '{print $1, $5, $3}' | while read -r ipaddr mac state; do
  host=$(getent hosts "$ipaddr" | awk '{print $2}' || true)
  host=${host:-"-"}
  if [ -n "$mac" ] && [ "$mac" != "FAILED" ]; then
    printf "  %-15s %-18s %s\n" "$ipaddr" "$host" "$mac"
    DEVICE_COUNT=$((DEVICE_COUNT+1))
  fi
done

sleep 0.2
if [ "$(ip -4 neigh show dev "$IFACE" | wc -l)" -lt 1 ]; then
  warn "No ARP entries found with 'ip neigh'. Trying 'arp -n'..."
  arp -n | awk '$4 ~ /[0-9a-f:]{17}/ {print $1, $3, $4}' | while read -r ipaddr host mac; do
    host=${host:-"-"}
    printf "  %-15s %-18s %s\n" "$ipaddr" "$host" "$mac"
  done
fi

TS=$(date +%Y%m%d_%H%M%S)
PCAPFILE="capture_${TS}.pcap"
info "Capture will be saved to: $PCAPFILE"

TCPDUMP_PIDS=()
cleanup(){
  info "Stopping capture..."
  for pid in "${TCPDUMP_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  sleep 0.2
  ok "Capture saved to $PCAPFILE"
  exit 0
}
trap cleanup INT TERM


tcpdump -i "$IFACE" -s 0 -w "$PCAPFILE" >/dev/null 2>&1 &
TCPDUMP_PIDS+=($!)
sleep 0.15


tcpdump -i "$IFACE" -n -l -tttt -q 2>/dev/null | \
while IFS= read -r line; do
  [ -z "$line" ] && continue

  proto=$(echo "$line" | awk '{print $2}')
  [ -z "$proto" ] && proto="?"

  if echo "$line" | grep -qE 'ARP,'; then

    src=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    dst=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
    size="-"
    printf "  %-15s -> %-15s %-7s %s\n" "${src:-?}" "${dst:-?}" "ARP" "$size"
    continue
  fi

  if echo "$line" | grep -qE '\bIP\b|\bIP6\b|\bUDP\b|\bTCP\b'; then
  
    body="${line#* }"
 
    srcdst=$(echo "$line" | sed -E 's/^[^ ]+ //; s/.*IP6? //; s/.*IP //; s/^[^ ]+ //')
    src=$(echo "$line" | awk -F' ' '{for(i=1;i<=NF;i++){ if($i==">"){print $(i-1); break}} }')
    dst=$(echo "$line" | awk -F' ' '{for(i=1;i<=NF;i++){ if($i==">"){print $(i+1); break}} }' | sed -E 's/:$//')
    strip_port() {
      echo "$1" | sed -E 's/:[0-9]+$//; s/\.[0-9]+$//'
    }
    src_ip=$(strip_port "$src")
    dst_ip=$(strip_port "$dst")

    len=$(echo "$line" | grep -oE 'length [0-9]+' | awk '{print $2}')
    len=${len:-"-"}

    if echo "$line" | grep -q 'UDP'; then proto="UDP"; fi
    if echo "$line" | grep -q 'TCP'; then proto="TCP"; fi
    if echo "$line" | grep -q 'ICMP'; then proto="ICMP"; fi

    printf "  %-15s -> %-15s %-7s %s bytes\n" "${src_ip:-?}" "${dst_ip:-?}" "${proto}" "${len}"
  else
    printf "  %s\n" "${line}"
  fi
done &

TCPDUMP_PIDS+=($!)
info "Transported packets (live):"
wait
