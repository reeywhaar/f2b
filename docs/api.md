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
saved.

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
not. `log` is a file the engine can read, of which the last `lines` are tried (2,000 by default,
20,000 at most), or `text` the lines themselves. `{ok, output, summary: {lines, ignored, matched,
missed}}`, `summary` null when fail2ban-regex did not get as far as counting.
