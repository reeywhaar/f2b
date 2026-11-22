# API

The engine's, on `/data/engine.sock`. The web passes every `/api` request to it as it came once
it is signed in, so the same paths work from a browser and, with `curl --unix-socket`, from the
host:

```sh
docker exec f2b-engine sh -c 'apk add -q curl && curl -s --unix-socket /data/engine.sock http://engine/api/jails'
```

JSON in, JSON out. Times are Unix seconds; durations are seconds, `-1` for good.

## Refusals

Every refusal is one shape, and the code is the contract; the message is written for a person
and may change.

```json
{ "ok": false, "code": "config_rejected", "message": "…", "output": "…" }
```

| status | code | |
| --- | --- | --- |
| 400 | `invalid` | a name, an address or a body that is not what is asked for |
| 404 | `not_found` | no such file, or no such endpoint |
| 409 | `conflict` | the file changed since the version given, or exists already |
| 422 | `config_rejected` | fail2ban would not start with that; `output` is what it said |
| 422 | `fail2ban` | fail2ban refused a command: a jail that is not running |
| 503 | `fail2ban` | fail2ban is not answering: starting, or stopped |
| 502 | `engine_unreachable` | the web could not reach the engine |
| 401 | `unauthenticated` | the web's: sign in first |

## The engine and fail2ban

`GET /api/engine` — `{version, fail2ban: {state, version, pid, since, restarts, lastExit}}`.
`state` is `starting`, `running` or `stopped`; `restarts` counts the times it stopped unasked.

`POST /api/engine/restart` — stops fail2ban and starts it again with the configuration on disk.
`202`.

`GET /api/log?after=&epoch=&limit=` — `{epoch, last, lines: [{seq, text}]}`: the latest lines,
or those after `after`. `epoch` names the engine's run; a cursor from another run starts over.

## Jails and bans

`GET /api/jails` — every running jail: `name`, `failedNow`, `failedTotal`, `bannedNow`,
`bannedTotal`, `logs`, `findTime`, `banTime`, `maxRetry`, and `file` and `filter`, the edited
file that defines it and the filter it names there.

`GET /api/bans` — every ban in force: `jail`, `ip`, `at`, `duration`, `until` (0 for good or
unknown), `count` (which ban of this address in this jail), `failures`, `matches` (the log lines).

`POST /api/bans` `{jail, ip}` — bans an address or a range in a running jail. `204`.

`DELETE /api/bans/{ip}?jail=` — lifts a ban in one jail, or in every jail without `jail`. fail2ban
also deletes the address's earlier bans in that jail from its database. `204`.

## History

`GET /api/history?jail=&ip=&before=&limit=` — `{bans, next}`: bans newest first, 50 by default,
up to 500. Pass `next` as `before` for the page after; `0` is the end.

`GET /api/stats?days=` — `{days, from, jails, perDay: [{day, total, byJail}], bans, ips, repeat,
lastDay, top: [{ip, bans, last, jails}]}` over the days up to today, UTC. `days` is 1 to 366, 30
by default.

## Files

Kinds are `jails` (`jail.d/`), `filters` (`filter.d/`), `actions` (`action.d/`) and `settings`
(`fail2ban.local`, `jail.local`, `paths-overrides.local`). Names end in `.local` or `.conf`.

`GET /api/files` — `{files: [{kind, name, size, modified, version, sections}]}`. `sections` are the
bracketed names in a file other than DEFAULT and INCLUDES: in a jail file, its jails.

`GET /api/files/{kind}/{name}` — `{file, content}`.

`PUT /api/files/{kind}/{name}` `{content, version}` — `version` is the file's as it was read, or
`""` for a new file. Checked with `fail2ban-client --test` against everything else, then written,
then fail2ban reloads: `{file, also, reload: {ok, output}}`. A reload that fails leaves the file
saved. One that leaves a jail without the actions configured for it is followed by a restart,
which `output` says.

`DELETE /api/files/{kind}/{name}?version=` — the same, without the file. `{file: null, reload}`.

`GET /api/files/{kind}/{name}/references` — `{files}`: the jail files, and `jail.local`, that name
this filter (`filter =`) or action (`action =`, `banaction =`), as references to them.

`POST /api/files/{kind}/{name}/rename` `{to, version, references}` — moves the file to `to`. With
`references`, the jail files that name it are changed to name the new one, and everything is
checked as one change and reloaded once: `{file, also, reload}`, `also` being the jail files
changed. Without it, a rename that leaves a jail naming what is gone is fail2ban's to refuse.
Settings files keep their names.

`POST /api/check` `{kind, name, content}` — whether fail2ban would start with that file as given,
or without it for `content: null`, changing nothing: `{ok, output}`.

`GET /api/stock` — `{filters, actions, other}`: fail2ban's own files, by name.

`GET /api/stock/{path}` — `{path, content}` of `filter.d/x.conf`, `action.d/x.conf` or a top-level
one such as `jail.conf`.

## The filter tester

`POST /api/regex` — fail2ban-regex, without resolving names:

```json
{
  "filter": "sshd[mode=aggressive]",
  "file": "sshd.local",
  "content": "…",
  "log": "/var/log/auth.log",
  "lines": 2000
}
```

`filter` is as a jail names it. `file` and `content` are a filter file as it would be, saved or
not. `log` is a file among the logs below, of which the last `lines` are tried (2,000 by default,
20,000 at most), or `text` the lines themselves; a log ending `.gz` is read through. One that is
not among them is `400`. `{ok, output, summary: {lines, ignored, matched, missed}}`, `summary`
null when fail2ban-regex did not get as far as counting.

## Logs

The logs the engine reads are what is mounted into its container read-only, and the directories
the running jails read logs in; never the data directory, or one holding it. A jail reading a log
in the data directory brings that log alone.

`GET /api/logs` — `{roots: [entry]}`: each of those places, `source` saying why it is one,
`mount` or `jail`.

`GET /api/logs/{path}` — `{entry, entries, more}` for a directory or a file among them, its path
without the first slash: `/api/logs/var/log`. `entries` is what a directory holds, directories
first, then files, each by name, and only those: 2,000 at most, with `more` true when there were
more. A link is followed only while it stays inside the place it is in. A path that is not among
the logs, or not there, is `404`.

An entry is `{name, path, dir, size, modified, jails, source}`: `jails` the running jails that
read it, `modified` Unix seconds.

## /api/v1, for scripts and agents

Tokens are the web's, issued to a signed-in browser and never to a token:

`GET /api/auth/tokens` — `{tokens: [{id, name, scope, created, lastUsed, expires, idle, ends,
expired}]}`, newest first. `ends` is when it stops working at the latest, unused from now; `0`
for never.

`POST /api/auth/tokens` `{name, scope, expiresIn, idleFor}` — `scope` is `read` or `write`; the
two lifetimes are each `1d`, `1w`, `30d`, `90d`, `180d`, `1y` or `never`. `201 {token, secret}`:
`secret` is the whole token, in this answer and nowhere else.

`DELETE /api/auth/tokens/{id}` — `204`. It stops working at once.

The same engine in JSON:API 1.1, at `/api/v1`, described route by route in
[`openapi.json`](../internal/engine/openapi.json), which the web also serves, unauthenticated, at
`/api/v1/openapi.json`. The interface keeps the plain API above.

Through the web, a request carries an API token, `Authorization: Bearer f2b_…`, or the browser's
session. Each route says in `x-f2b-scope` which token takes it: a read token every `read` route,
a write token every route. Trying a filter (`POST /api/v1/regex-tests`) and checking a file
(`POST /api/v1/config-checks`) change nothing, so they are `read`. The web says which scope a
request has in `F2B-Scope`; one to the socket without it is the socket's own caller, trusted as
the web is.

What JSON:API asks, and what this adds:

- `application/vnd.api+json` both ways: another body is `415`, an Accept naming it only with
  parameters other than `ext` and `profile` is `406`.
- A document is `{jsonapi, data, meta, links}`; a refusal is `{jsonapi, errors: [{status, code,
  title, detail, meta}]}`, with the codes of the refusals above and `meta.output` for
  `config_rejected`.
- Query parameters are `filter[…]` and `page[…]`: `filter[jail]`, `filter[ip]`, `filter[kind]`,
  `filter[days]`, `filter[dir]`, `page[before]`, `page[after]`, `page[epoch]`, `page[size]`. `links.next` is the
  page after, where there is one.
- A ban in force is `bans` with the id `jail/ip`, and is lifted at
  `DELETE /api/v1/jails/{jail}/bans/{ip}`, a range's slash escaped as `%2F`. A ban in the database
  is `history-bans`, with the database's id.
- A file is `files` with the id `kind/name`. Its `ETag` is its version: `PATCH` and `DELETE`, and
  a rename, send it back in `If-Match`. Without it, `428`; against an older one, `412`. A write's
  `meta` is what the plain API's `{also, reload}` is.
- A rename, `POST /api/v1/files/{kind}/{name}/rename`, is an action rather than a resource, and
  takes `{meta: {to, references}}`.
- The logs are `log-files` with the path as id: `GET /api/v1/log-files` the places,
  `?filter[dir]=/var/log` what one directory holds with `meta.more`, and
  `GET /api/v1/log-files/var/log/auth.log` one.
