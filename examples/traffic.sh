#!/usr/bin/env bash
# Send harmless, WAF-tripping requests to the example stack from spoofed source
# addresses, so the threat map has something to show.
#
#   ./traffic.sh            # one round of attacks from every source below
#   ./traffic.sh 5          # five rounds
#   HTTPS_PORT=9443 ./traffic.sh
#
# The example stack trusts X-Forwarded-For from anywhere (REAL_IP_FROM 0.0.0.0/0,
# test only!), so BunkerWeb sees each request as coming from the address below and
# resolves its country with its own GeoIP database: the map shows whatever that
# database says, the comments are only indicative.
set -euo pipefail

ROUNDS="${1:-1}"
TARGET="https://127.0.0.1:${HTTPS_PORT:-8443}"
# app1 blocks; app2 runs in SECURITY_MODE=detect (logged, not denied)
HOSTS=(app1.example.com app1.example.com app1.example.com app2.example.com)

SOURCES=(
  8.8.8.8         # US
  114.114.114.114 # CN
  77.88.8.8       # RU
  46.4.0.1        # DE
  94.142.241.111  # NL
  80.67.169.12    # FR
  212.58.244.20   # GB
  200.160.2.3     # BR
  168.126.63.1    # KR
  165.21.83.88    # SG
  203.162.4.191   # VN
  196.25.1.1      # ZA
  139.130.4.5     # AU
  195.175.39.39   # TR
  202.134.0.155   # ID
  133.242.0.1     # JP
)

ATTACKS=(
  "/?q=<script>alert(1)</script>"
  "/?id=1%27%20OR%20%271%27=%271"
  "/..%2f..%2f..%2fetc%2fpasswd"
  "/?cmd=;cat%20/etc/passwd"
  "/wp-login.php"
  "/.env"
)

hit() {
  local host="${HOSTS[RANDOM % ${#HOSTS[@]}]}"
  curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Host: $host" -H "X-Forwarded-For: $1" -A "${3:-Mozilla/5.0 (threatmap example)}" \
    "$TARGET$2" || echo "ERR"
}

for ((round = 1; round <= ROUNDS; round++)); do
  for ip in "${SOURCES[@]}"; do
    # a random subset of the attacks, so the countries do not all look alike
    for attack in "${ATTACKS[@]}"; do
      ((RANDOM % 3 == 0)) && continue
      printf '%s %s -> %s\n' "$ip" "$attack" "$(hit "$ip" "$attack")"
      sleep 0.05
    done
  done
  # a scanner hammering one address trips Bad Behavior / Limit as well
  scanner="${SOURCES[RANDOM % ${#SOURCES[@]}]}"
  for i in $(seq 1 15); do
    hit "$scanner" "/admin-$i.php" "sqlmap/1.8" >/dev/null
  done
  echo "round $round/$ROUNDS done (scanner: $scanner)"
done
