#!/bin/sh
# Runs a built engine image through what it is for, with a real fail2ban and a real firewall in
# the container's own network namespace: a filter and a jail saved through the API, failures
# written to a log, the ban that follows in fail2ban and in iptables, an unban, a jail's action
# changed for one of another name, a configuration fail2ban refuses, the filter tester, a restart
# that puts the ban back, a rename, and /api/v1 as a read and a write token reach it.
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
body = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
headers = {}
if body:
    headers["Content-Type"] = "application/vnd.api+json" if path.startswith("/api/v1/") else "application/json"
# The scope the web would pass on for a token, when one is given.
if len(sys.argv) > 4:
    headers["F2B-Scope"] = sys.argv[4]
c = Conn("engine")
c.request(method, path, body=body, headers=headers)
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

echo "==> a jail given an action under a new name has it: fail2ban's reload alone drops it"
since=$(api GET /api/engine | sed 's/.*"since":\([0-9]*\).*/\1/')
version=$(api GET /api/files/jails/app.local | sed 's/.*"version":"\([0-9a-f]*\)".*/\1/')
out=$(api PUT /api/files/jails/app.local "{\"content\":\"[app]\\nenabled = true\\nfilter = app\\nlogpath = /logs/app.log\\nbackend = polling\\nmaxretry = 3\\nbantime = 1h\\nbanaction = iptables-multiport\\nport = 1:65535\\n\",\"version\":\"$version\"}")
case "$out" in 200*'"reload":{"ok":true'*'restarting'*) ;; *) fail "new action: $out" ;; esac
for _ in $(seq 1 60); do
  out=$(api GET /api/engine 2>&1 || true)
  now=$(echo "$out" | sed 's/.*"since":\([0-9]*\).*/\1/')
  case "$out" in *'"state":"running"'*) [ "$now" != "$since" ] && break ;; esac
  sleep 0.5
done
case "$out" in *'"state":"running"'*) [ "$now" != "$since" ] || fail "fail2ban did not restart: $out" ;; *) fail "fail2ban did not come back: $out" ;; esac
out=$(api POST /api/bans '{"jail":"app","ip":"203.0.113.10"}')
case "$out" in 204*) ;; *) fail "ban by hand: $out" ;; esac
wait_for '203.0.113.10' docker exec "$name" iptables -S f2b-app
wait_for 'multiport' docker exec "$name" iptables -S INPUT
api DELETE '/api/bans/203.0.113.10?jail=app' >/dev/null

echo "==> a jail fail2ban refuses is refused, and not written"
out=$(api PUT /api/files/jails/bad.local '{"content":"[bad]\nenabled = true\nfilter = nosuchfilter\nlogpath = /logs/app.log\n","version":""}')
case "$out" in 422*config_rejected*nosuchfilter*) ;; *) fail "refusal: $out" ;; esac
docker exec "$name" test ! -e /data/fail2ban/jail.d/bad.local || fail "a refused file was written"

echo "==> the tester runs fail2ban-regex"
out=$(api POST /api/regex '{"filter":"app","log":"/logs/app.log"}')
case "$out" in 200*'"matched":3'*) ;; *) fail "regex: $out" ;; esac
# One line pasted with no newline after it, which fail2ban-regex alone would leave uncounted.
out=$(api POST /api/regex '{"filter":"app","text":"{\"msg\":\"password refused\",\"ip\":\"203.0.113.3\"}"}')
case "$out" in 200*'"lines":1,'*'"matched":1'*) ;; *) fail "pasted line: $out" ;; esac

echo "==> a rename that would leave a jail naming nothing is refused; with the jail, it is one change"
version=$(api GET /api/files/filters/app.local | sed 's/.*"version":"\([0-9a-f]*\)".*/\1/')
out=$(api POST /api/files/filters/app.local/rename "{\"to\":\"app-auth.local\",\"version\":\"$version\",\"references\":false}")
case "$out" in 422*config_rejected*) ;; *) fail "rename alone: $out" ;; esac
out=$(api POST /api/files/filters/app.local/rename "{\"to\":\"app-auth.local\",\"version\":\"$version\",\"references\":true}")
case "$out" in 200*'"also":[{"kind":"jails","name":"app.local"}]'*'"reload":{"ok":true'*) ;; *) fail "rename: $out" ;; esac
docker exec "$name" grep -q '^filter = app-auth$' /data/fail2ban/jail.d/app.local || fail "the jail names the old filter"
docker exec "$name" test ! -e /data/fail2ban/filter.d/app.local || fail "the old name is still there"
wait_for '"name":"app"' api GET /api/jails

echo "==> /api/v1 answers in JSON:API, and a read scope cannot ban"
out=$(api GET /api/v1/jails "" read)
case "$out" in 200*'"jsonapi":{"version":"1.1"}'*'"type":"jails","id":"app"'*) ;; *) fail "v1 jails: $out" ;; esac
ban='{"data":{"type":"bans","attributes":{"ip":"203.0.113.11"},"relationships":{"jail":{"data":{"type":"jails","id":"app"}}}}}'
out=$(api POST /api/v1/bans "$ban" read)
case "$out" in 403*'"code":"forbidden"'*) ;; *) fail "v1 ban with a read scope: $out" ;; esac
out=$(api POST /api/v1/bans "$ban" write)
case "$out" in 201*'"id":"app/203.0.113.11"'*) ;; *) fail "v1 ban: $out" ;; esac
wait_for '203.0.113.11' docker exec "$name" iptables -S f2b-app
out=$(api DELETE /api/v1/jails/app/bans/203.0.113.11 "" write)
case "$out" in 204*) ;; *) fail "v1 unban: $out" ;; esac

echo "==> healthy"
docker exec "$name" f2b healthcheck engine || fail "healthcheck"

echo "OK"
