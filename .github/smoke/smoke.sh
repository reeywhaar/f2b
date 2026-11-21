#!/bin/sh
# Runs a built engine image through what it is for, with a real fail2ban and a real firewall in
# the container's own network namespace: a filter and a jail saved through the API, failures
# written to a log, the ban that follows in fail2ban and in iptables, an unban, a configuration
# fail2ban refuses, the filter tester, a restart that puts the ban back, and a rename.
#
#   docker build --target engine -t f2b-engine:smoke . && IMAGE=f2b-engine:smoke .github/smoke/smoke.sh
set -eu

IMAGE="${IMAGE:?set IMAGE to the engine image to try}"
name="f2b-smoke-$$"
volume="$name-data"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  docker logs "$name" 2>&1 | tail -n 40 >&2
  exit 1
}

# The API over the engine's socket, with the Python fail2ban already brings: no client to add.
api() {
  docker exec -i "$name" python3 - "$@" <<'PY'
import http.client, socket, sys
class Conn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(150)
        self.sock.connect("/data/engine.sock")
method, path = sys.argv[1], sys.argv[2]
body = sys.argv[3] if len(sys.argv) > 3 else None
c = Conn("engine")
c.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
r = c.getresponse()
print(r.status, r.read().decode())
PY
}

# Polls a command until its output matches, a bounded number of times.
wait_for() {
  pattern="$1"; shift
  for _ in $(seq 1 60); do
    out=$("$@" 2>&1 || true)
    case "$out" in *$pattern*) return 0 ;; esac
    sleep 0.5
  done
  fail "waited for '$pattern' from $*; last: $out"
}

docker volume create "$volume" >/dev/null
docker run -d --name "$name" --cap-add NET_ADMIN --cap-add NET_RAW -v "$volume:/data" "$IMAGE" >/dev/null

echo "==> fail2ban starts"
wait_for '"state":"running"' api GET /api/engine

echo "==> a filter and a jail are saved, and fail2ban reloads with them"
docker exec "$name" sh -c 'mkdir -p /logs && : > /logs/app.log'
out=$(api PUT /api/files/filters/app.local '{"content":"[Definition]\nfailregex = ^\\{.*\"msg\":\"password refused\".*\"ip\":\"<ADDR>\"\n","version":""}')
case "$out" in 200*'"reload":{"ok":true'*) ;; *) fail "filter: $out" ;; esac
out=$(api PUT /api/files/jails/app.local '{"content":"[app]\nenabled = true\nfilter = app\nlogpath = /logs/app.log\nbackend = polling\nmaxretry = 3\nbantime = 1h\nbanaction = iptables-allports\n","version":""}')
case "$out" in 200*'"reload":{"ok":true'*) ;; *) fail "jail: $out" ;; esac
wait_for '"name":"app"' api GET /api/jails

echo "==> failures in the log are a ban, in fail2ban and in the firewall"
for _ in 1 2 3; do
  docker exec "$name" sh -c 'echo "{\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"msg\":\"password refused\",\"ip\":\"203.0.113.9\"}" >> /logs/app.log'
done
wait_for '"ip":"203.0.113.9"' api GET /api/bans
wait_for '203.0.113.9' docker exec "$name" iptables -S f2b-app
wait_for '"ip":"203.0.113.9"' api GET '/api/history?jail=app'

echo "==> the ban survives a restart of fail2ban"
api POST /api/engine/restart >/dev/null
wait_for '"state":"running"' api GET /api/engine
wait_for '"ip":"203.0.113.9"' api GET /api/bans

echo "==> an unban lifts it"
out=$(api DELETE '/api/bans/203.0.113.9?jail=app')
case "$out" in 204*) ;; *) fail "unban: $out" ;; esac
wait_for '"bans":[]' api GET /api/bans

echo "==> a jail fail2ban refuses is refused, and not written"
out=$(api PUT /api/files/jails/bad.local '{"content":"[bad]\nenabled = true\nfilter = nosuchfilter\nlogpath = /logs/app.log\n","version":""}')
case "$out" in 422*config_rejected*nosuchfilter*) ;; *) fail "refusal: $out" ;; esac
docker exec "$name" test ! -e /data/fail2ban/jail.d/bad.local || fail "a refused file was written"

echo "==> the tester runs fail2ban-regex"
out=$(api POST /api/regex '{"filter":"app","log":"/logs/app.log"}')
case "$out" in 200*'"matched":3'*) ;; *) fail "regex: $out" ;; esac

echo "==> a rename that would leave a jail naming nothing is refused; with the jail, it is one change"
version=$(api GET /api/files/filters/app.local | sed 's/.*"version":"\([0-9a-f]*\)".*/\1/')
out=$(api POST /api/files/filters/app.local/rename "{\"to\":\"app-auth.local\",\"version\":\"$version\",\"references\":false}")
case "$out" in 422*config_rejected*) ;; *) fail "rename alone: $out" ;; esac
out=$(api POST /api/files/filters/app.local/rename "{\"to\":\"app-auth.local\",\"version\":\"$version\",\"references\":true}")
case "$out" in 200*'"also":[{"kind":"jails","name":"app.local"}]'*'"reload":{"ok":true'*) ;; *) fail "rename: $out" ;; esac
docker exec "$name" grep -q '^filter = app-auth$' /data/fail2ban/jail.d/app.local || fail "the jail names the old filter"
docker exec "$name" test ! -e /data/fail2ban/filter.d/app.local || fail "the old name is still there"
wait_for '"name":"app"' api GET /api/jails

echo "==> healthy"
docker exec "$name" f2b healthcheck engine || fail "healthcheck"

echo "OK"
