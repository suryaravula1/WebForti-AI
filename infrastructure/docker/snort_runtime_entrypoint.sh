#!/usr/bin/env bash
set -euo pipefail

mkdir -p /tmp/webforti-snort
printf '%s\n' "${SNORT_RULE:-}" > /tmp/webforti-snort/webforti.rules
touch /tmp/webforti-snort/alert_fast.txt

echo "WEBFORTI_SNORT_START image=openeuler/snort3:3.9.5.0-oe2403sp1 iface=eth0"
tail -n +1 -F /tmp/webforti-snort/alert_fast.txt 2>/dev/null &
TAIL_PID="$!"
snort \
  --daq-dir /usr/local/lib/daq \
  --daq afpacket \
  --daq-mode passive \
  -i eth0 \
  -k none \
  -l /tmp/webforti-snort \
  -c /snort3/lua/snort.lua \
  -R /tmp/webforti-snort/webforti.rules \
  -A alert_fast &

SNORT_PID="$!"
python3 /sensor/snort_sensor_proxy.py &
PROXY_PID="$!"

cleanup() {
  kill "$PROXY_PID" "$SNORT_PID" "$TAIL_PID" 2>/dev/null || true
  wait "$PROXY_PID" "$SNORT_PID" "$TAIL_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait "$PROXY_PID"
