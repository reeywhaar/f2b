# Deploy

## Two containers, one volume, one socket

fail2ban bans by writing the host's firewall, which takes the host's network namespace and
`NET_ADMIN`. A container in the host's network cannot also be on the Docker network
caddy-docker-proxy reaches containers on, and putting the interface on a host port instead would
publish it to the internet beside Caddy. So the engine and the web are two images, and the only
thing between them is a unix socket in the volume both mount.

The engine trusts whoever connects to the socket, and listens on nothing else. Reaching the
socket takes the data volume, which is already the configuration, the database and the key that
signs cookies; checking a second secret there would protect nothing.

The web knows nothing of fail2ban. It signs people in, and passes every other `/api` request to
the socket as it came, minus the cookie. So the API the interface uses is the engine's, and is
written down once, in [api.md](api.md).

## The engine needs the host's network, NET_ADMIN and NET_RAW

```yaml
network_mode: host
cap_add: [NET_ADMIN, NET_RAW]
```

iptables runs on the nf_tables backend, as Docker writes its own rules on any current host, and as
linuxserver/fail2ban does. A host still on legacy iptables would see the rules land in tables
Docker does not read.

## Every log is mounted read-only at the path the jail names

fail2ban runs inside the engine, so a jail's `logpath` is a path in the engine's container. Mount
each log directory read-only, at the same path on both sides or at the one the jails name:

```yaml
volumes:
  - /var/log:/var/log:ro
  - /srv/logs:/remotelogs/docker:ro
```

The stock jails' `%(sshd_log)s` is `/var/log/auth.log`, from fail2ban's `paths-debian.conf`; a host
logging sshd elsewhere sets `sshd_log` in `paths-overrides.local`, under Settings. There is no
journal: the engine has no systemd, and sshd's jail reads the file rsyslog writes.

Read-only is also how the engine tells a log directory from the rest of its container. The filter
tester, and the list of logs it picks from, read only what is mounted read-only and the
directories the running jails read logs in, and never `/data`: the tester can read any file it is
pointed at, an API token that only reads may point it, and `/data` holds the session key and the
tokens. The engine finds the mounts in `/proc/self/mountinfo` at start, and logs them; it leaves
out the kernel's, `/run/secrets`, and anything that is `/data` or holds it. A log mounted
read-write is still read by its jail, and the tester reaches it where a jail reads it.

## A published container's traffic is banned in DOCKER-USER

A connection to a port Docker publishes never passes `INPUT`, so a ban there does not stop it.
Ban in `DOCKER-USER`, the chain Docker leaves for this; ban every port, so somebody refused at one
service does not carry on at the next; and ban every protocol, because Caddy serves HTTP/3 on UDP
443, and a browser that has used it once keeps to it:

```ini
# jail.local
[DEFAULT]
banaction = iptables-allports
chain     = DOCKER-USER
protocol  = all
```

`chain` and `protocol` are keys of the jail, not options of the action:
`iptables-allports[chain=DOCKER-USER]` is undone without a word, because jail.conf hands every
action `chain` and `protocol` after it, `INPUT` and `tcp` unless the jail sets them. `all` takes
an allports action; one naming ports takes `protocol = tcp,udp`, as iptables refuses `-p all`
with them.

sshd, which is not in a container, is banned in `INPUT`: `chain = INPUT` in its jail.

## What fail2ban runs with is composed, and nothing in /data/fail2ban is overwritten

fail2ban reads one configuration directory. The engine builds it, in the container, before every
start and after every save:

1. fail2ban's package configuration, from the image, without its `jail.d` and `fail2ban.d`. The
   Alpine package enables an sshd jail reading `/var/log/messages`; which jails run is the edited
   files' to say.
2. Every file in `/data/fail2ban` that fail2ban would read: `jail.d/`, `filter.d/` and
   `action.d/` files ending in `.local` or `.conf`, and the top-level `fail2ban.local`,
   `jail.local` and `paths-overrides.local`. Anything else there is left out.
3. `fail2ban.d/00-f2b.conf`, under `[DEFAULT]`, which everything above overrides: a database
   purge age of 90 days rather than fail2ban's one, so the history has something to show.
4. `fail2ban.d/zz-f2b.local`, read last, under `[Definition]`, which nothing overrides: the log
   goes to the engine's output, the socket and pid file are the engine's, and the database is
   `/data/fail2ban.sqlite3`.

So an image with a newer fail2ban brings its newer stock filters, and an edit never touches them.

## A save is checked against everything, then written, then reloaded

A change is composed with everything else into a scratch directory, and `fail2ban-client
--test` reads it as fail2ban would on starting. A refusal is the API's `422 config_rejected`,
carrying fail2ban's own lines, and nothing is written. Accepted, the file is written whole —
beside itself, then renamed over — the live configuration is composed again, and `fail2ban-client
reload` hands it to fail2ban, which keeps its bans across it. A reload that fails after a passed
check leaves the file saved and says so; fail2ban carries on as it was.

fail2ban reads a filter only when a jail uses it, so a broken filter no jail names yet passes the
check, and is refused when a jail first names it.

A reload that leaves a jail without the actions configured for it is followed by a restart.
fail2ban 1.1's reload drops an action a jail gains under a new name, as changing its `banaction`
does, and its bans then go unenforced; a restart starts the action and puts the bans back from the
database. After a save of a jail or a setting, the engine compares each running jail's actions with
what `fail2ban-client -d` says the configuration gives it, and the reply's `reload.output` says when
it restarted.

A rename is the same, with more in it: the file under its new name, the old name gone, and, when
asked, every jail file that names it changed to name the new one. A jail names a filter or an
action by its file's name, so renaming one alone would leave the jail naming nothing, which
fail2ban refuses. All of it is checked as one change, written new names first, and reloaded once.

A save carries the version of the file it was made from. A file that changed on disk since —
from a shell, or another browser — is a `409`, and the interface offers to open it again rather
than overwrite.

## fail2ban runs as the engine's child, and starts again when it stops

`fail2ban-client -f start`, in the foreground, under tini. Its log is the engine's output, so
`docker logs f2b-engine` has it beside the engine's own, and the engine keeps the last 5,000
lines for the interface and every line in `/data/fail2ban.log`, rotated once at 10 MB.

When fail2ban stops without being asked, it is started again after a second, and then after
twice as long each time it fails to stay up, up to a minute; one that ran a minute starts over at
a second. A configuration fail2ban cannot start with, edited from outside, is a loop the log
explains, and saving a fix from the interface starts it at once.

Stopping fail2ban takes its rules out of the firewall, and starting it puts the bans still in
force back from its database. The engine gives it eight seconds on the way down; a compose file
gives the container thirty with `stop_grace_period: 30s`.

## The history is fail2ban's own database, read

The engine keeps nothing of its own about bans. The overview's counts and chart and the history
are queries on `fail2ban.sqlite3`, opened read-only. Its purge age is ninety days unless
`fail2ban.local` sets `dbpurgeage`.

**Unbanning by hand also removes that address's earlier bans in that jail from the database.**
That is fail2ban's: its `unbanip` deletes them. A ban that runs out on its own stays in the
history.

## Every wrong password, and every refused token, is one line, for fail2ban

The web bans nobody itself. Each refused password, and each refused API token, is logged as

```
{"time":"…","level":"WARN","msg":"password refused","ip":"203.0.113.7"}
{"time":"…","level":"WARN","msg":"token refused","ip":"203.0.113.7"}
```

and a jail on the web's own log does the rest:

```ini
# filter.d/f2b.local
[Definition]
failregex = ^\{.*"msg":"(?:password|token) refused".*"ip":"<ADDR>"
ignoreregex =
```

```ini
# jail.d/f2b.local
[f2b]
enabled   = true
filter    = f2b
logpath   = /remotelogs/docker/f2b-web.log
banaction = iptables-allports
chain     = DOCKER-USER
protocol  = all
maxretry  = 5
bantime   = 1d
```

The line names the address and nothing else: a password typed into the wrong field is common
enough that logging what was typed would log passwords, and a token pasted wrong is most of a
token. Sign-ins are also limited to five quick attempts an address, and thirty across all of them;
refused tokens spend the same five.

## The caller is the first X-Forwarded-For hop that is not a trusted proxy

The interface sits behind Caddy, so the connection the web sees is Caddy's. Each proxy appends
who it accepted to `X-Forwarded-For`, so the web reads the header right to left, stepping over
trusted proxies; the first hop that is not one is the caller. From a peer that is not a trusted
proxy, the header is the caller's own claim, and believing it would let a stranger choose the
address fail2ban bans — yours, say.

`F2B_TRUSTED_PROXIES` names them: addresses, ranges, `private`, or `none`, separated by commas or
spaces. `private`, the default, is 10/8, 172.16/12, 192.168/16, fc00::/7 and loopback: right for
Caddy on the same Docker network. Behind a CDN, an iptables ban does nothing — the address never
connects to this host — and a jail there needs the CDN's own ban action.

## The session is a signed cookie, and nothing is stored per sign-in

A cookie says when it ends, thirty days on and moved on by a visit each day, and carries a MAC
over that and the password, under a key in `/data/session.key`. So there is no session table and
no database of the web's own. Changing `ADMIN_PASSWORD` signs every browser out; so does Sign
out everywhere, which replaces the key.

## An API token is a second way in, to /api/v1 only, and the engine decides what it may do

A script or an agent gets a token from Config rather than the password. The web issues it, shows
it once, and keeps a digest of it in `/data/tokens.json`, which only the web writes; the file is
no use to whoever reads it. A token is `f2b_`, an id that finds it, and a secret checked against
the digest.

Each token reads, or reads and writes, and ends after a lifetime and after a time unused, each a
day, a week, 30, 90 or 180 days, a year, or never. Its last use is kept to the minute and written
at most once a minute, so an agent polling every second is not a write every second. A token
works only on `/api/v1`, and never on the routes that make and end tokens: a leaked one cannot
make itself another.

The web says which scope a request has in `F2B-Scope`, set over whatever the request carried: the
token's, or `write` for a signed-in browser. Each `/api/v1` route in the engine says whether it
writes, and refuses a read scope if it does, so what a scope may do is decided where the routes
are, and the web still knows nothing of fail2ban. Trying a filter and checking a file are POSTs
that change nothing, and a read token may.

## Moving from linuxserver/fail2ban

The files are the same files; they move into `/data/fail2ban` once, and every mount of a single
file goes.

1. Stop the old container first. Two fail2bans writing the same chains undo each other.
2. Copy the jails and filters into the new volume, and fail2ban's database if its bans and
   history should come too. From the old project's directory, where its `config/` is:

   ```sh
   docker compose -f /path/to/f2b/compose.yml up --no-start engine
   docker run --rm -v f2b_data:/data -v "$PWD/config:/old:ro" alpine sh -c '
     mkdir -p /data/fail2ban/jail.d /data/fail2ban/filter.d /data/fail2ban/action.d &&
     cp /old/jail.d/* /data/fail2ban/jail.d/ &&
     cp /old/filter.d/* /data/fail2ban/filter.d/'
   # The database is where the old dbfile put it: /config/fail2ban/fail2ban.sqlite3 by default.
   docker cp fail2ban:/config/fail2ban/fail2ban.sqlite3 old.sqlite3
   docker run --rm -v f2b_data:/data -v "$PWD/old.sqlite3:/old.sqlite3:ro" alpine \
     cp /old.sqlite3 /data/fail2ban.sqlite3
   ```

   `f2b_data` is the data volume of a compose project named `f2b`; `docker volume ls` says.
   `docker cp` reads a stopped container as well as a running one.
3. `dbfile` set under `[DEFAULT]` in a jail file does nothing and can go: the database's place
   is the engine's to say.
4. Start it, and look at the overview: every jail that should run is listed, or the log says why
   one is not.

linuxserver's image carries a few filters fail2ban's package does not, `authelia-auth` and
`airsonic-auth` among them; a jail using one needs it copied into `filter.d` too. Its paths file
is its own as well: a jail that relied on one of its `%(…_log)s` names should name the file.
