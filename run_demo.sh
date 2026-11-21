#!/bin/sh
# Runs the demo: the web against a stand-in engine with invented jails, bans and logs, made
# afresh on every run. The sign-in is kept in the demo's volume, so a browser signed in stays
# signed in. Ctrl-C stops it. See README.md.
#
#   ./run_demo.sh              on http://localhost:8080
#   ./run_demo.sh --fresh      signed out: the volume is made anew
#   DEMO_PORT=9090 ./run_demo.sh
set -eu

cd "$(dirname "$0")"
port="${DEMO_PORT:-8080}"
compose="docker compose -f demo/compose.yml"

logs=""
stop() {
  trap - EXIT INT TERM
  [ -n "$logs" ] && kill "$logs" 2>/dev/null
  echo
  echo "Stopping the demo…"
  $compose down --remove-orphans >/dev/null 2>&1 || true
}
trap stop EXIT INT TERM

# Anything left from a run that was not stopped goes first, and with --fresh the volume too.
if [ "${1:-}" = "--fresh" ]; then
  $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
else
  $compose down --remove-orphans >/dev/null 2>&1 || true
fi
$compose up --build --detach --wait

echo
echo "Ready: http://f2b.localhost:$port"
echo "The password is demodemo. Ctrl-C stops the demo."
echo
# In the background and waited for, so a signal ends the wait at once and the demo goes down.
$compose logs --follow --no-log-prefix engine &
logs=$!
wait "$logs"
