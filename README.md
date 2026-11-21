# f2b

fail2ban with an API, and an interface to it. Jails, filters and actions are files, edited in
the browser; a change is tried on fail2ban before it is saved, and fail2ban reloads with it.

- **Edit jails, filters and actions** in an editor that knows fail2ban's files: sections, keys,
  values carrying on over lines, `%(interpolation)s` and `<HOST>`. Cmd-S saves.
- **A save fail2ban would refuse is refused**, with fail2ban's own words, and nothing is written.
  One it accepts is written, and fail2ban reloads, keeping its bans.
- **Try a filter on a log** before saving it: fail2ban-regex over the end of a log a jail reads,
  any file the engine can read, or lines pasted in.
- **fail2ban's own filters and actions**, to read and to override in one press.
- **Who is banned now**, where, since when and until when, and the log lines that did it. Lift
  a ban, or ban an address or a range by hand.
- **The history**: bans per day by jail, the most banned addresses, every ban fail2ban's
  database holds, for ninety days unless fail2ban.local says otherwise.
- **fail2ban's log**, following along.
- **One password**, from the environment. Every wrong one is a line for fail2ban to read.

## Two containers

fail2ban writes the host's firewall, so it runs in the host's network with `NET_ADMIN`; a
container there cannot join the network Caddy reaches containers on. So there are two images:

| image | | network |
| --- | --- | --- |
| `ghcr.io/reeywhaar/f2b-engine` | fail2ban, iptables, and the API, on a socket in `/data` | the host's |
| `ghcr.io/reeywhaar/f2b-web` | the interface and the sign-in; every request past it goes to the socket | Caddy's |

They share one volume, `/data`, and nothing else. The engine listens on no port.

## Run it

Behind [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy):

```yaml
# compose.yml
services:
  engine:
    image: ghcr.io/reeywhaar/f2b-engine:v1
    container_name: f2b-engine
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    # fail2ban takes its rules out of the firewall on the way down.
    stop_grace_period: 30s
    volumes:
      - data:/data
      # Every log a jail reads, read-only, at the path the jail names: the host's, and the
      # containers' as a log collector writes them out.
      - /var/log:/var/log:ro
      - /srv/logs:/remotelogs/docker:ro

  web:
    image: ghcr.io/reeywhaar/f2b-web:v1
    container_name: f2b-web
    restart: unless-stopped
    environment:
      ADMIN_PASSWORD: … # openssl rand -base64 24
      F2B_LABEL: web-1 # optional: which server this is, in the header
    volumes:
      - data:/data
    networks: [caddy]
    labels:
      caddy: f2b.example.com
      caddy.reverse_proxy: "{{upstreams 80}}"

volumes:
  data:

networks:
  caddy:
    external: true
```

```sh
docker compose up -d
```

Open it, sign in with the password, and add jails under Config: a jail names a log, a filter,
and what a ban does. [docs/deploy.md](docs/deploy.md) has the rest: where the files go, which
ban action blocks a container, a jail for this interface's own sign-in, and moving from
linuxserver/fail2ban.

| variable | read by | |
| --- | --- | --- |
| `ADMIN_PASSWORD` | web | *required.* At least 8 characters. Changing it signs every browser out |
| `F2B_PUBLIC_URL` | web | where the interface is opened; only an `http://` one matters, sending the cookie without Secure |
| `F2B_TRUSTED_PROXIES` | web | whose `X-Forwarded-For` is believed; `private` by default |
| `F2B_LABEL` | web | names this server in the header and the tab's title, for telling several apart |
| `F2B_DATA_DIR` | both | the shared directory; `/data` by default |
| `F2B_LOG_LEVEL` | both | `debug`, `info`, `warn` or `error` |

## The data directory

```
/data/
  fail2ban/           what is edited: jail.d/, filter.d/, action.d/, fail2ban.local, jail.local
  fail2ban.sqlite3    fail2ban's database: its bans, and their history
  fail2ban.log        fail2ban's log, as the engine captured it
  engine.sock         the engine's API, which the web reaches
  session.key         what signs the sign-in cookie
```

The files in `fail2ban/` are plain files. Anything that edits them works; the engine reads them
whenever fail2ban starts or reloads, and the interface's Restart does that.

## The demo

```sh
./run_demo.sh
```

builds the web image and runs it against `f2b demo`, a stand-in engine with six invented jails,
ninety days of invented bans and logs that the filters match, banning somebody new every half
minute. Open <http://f2b.localhost:8080>; the password is **demodemo**. Ctrl-C stops it;
`--fresh` signs every browser out. Everything is real but fail2ban: the files are edited on disk,
the history is read from a database in fail2ban's own shape, and only the jails, the bans and
fail2ban-regex are stood in for, the last by Go's regexp, which has no lookahead.

## Develop

Go 1.27 and Node 26.

```sh
go test ./...                                   # the engine, the web, the history, the socket
npm --prefix web ci && npm --prefix web test    # the interface
```

From a checkout, against the stand-in engine, with the data in `private/demo/data`:

```sh
npm --prefix web run build
F2B_DATA_DIR=$PWD/private/demo/data go run . demo &
F2B_DATA_DIR=$PWD/private/demo/data ADMIN_PASSWORD=demodemo F2B_PUBLIC_URL=http://localhost go run . web
```

`npm --prefix web run dev` serves the interface with reloading and sends `/api` to port 80.
`npm --prefix web run screenshots` photographs a running demo. `.github/smoke/smoke.sh` runs a
built engine image through a real fail2ban and a real firewall, as CI does before publishing:

```sh
docker build --target engine -t f2b-engine:smoke . && IMAGE=f2b-engine:smoke .github/smoke/smoke.sh
```

```
main.go             the command line: engine, web, demo, healthcheck
internal/
  engine/           fail2ban supervised, its configuration composed, the API, the log
  f2bsock/          fail2ban's own socket protocol, pickles and all
  history/          fail2ban's database, read
  webui/            the sign-in, the cookie, the way through to the engine, the bundle
  demo/             the stand-in engine
  config/ app/      the environment, and what is fixed
web/                the interface: React, Tailwind, prism-code-editor
demo/ run_demo.sh   the demo
docs/               decisions: deploy, the API, conventions
```

How the engine composes fail2ban's configuration and why, and every other decision, is in
[docs/deploy.md](docs/deploy.md); the API in [docs/api.md](docs/api.md); how the code is
written in [docs/conventions.md](docs/conventions.md).
