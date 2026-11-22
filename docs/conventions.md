# Conventions

The same as mailio's and appstoreanalytics', so they read as one codebase. Settled once here so
it is not re-argued in review.

## Words

One name per thing, in identifiers, the API, the docs and the interface.

| word | means | in code |
| --- | --- | --- |
| engine | the container running fail2ban, and its API on the socket | `engine`, `f2b engine` |
| web | the container serving the interface and the sign-in | `webui`, `f2b web` |
| jail | fail2ban's: a log, a filter, and what a ban does | `Jail`, `jails` |
| filter | fail2ban's: what a failure looks like in a log | `filters`, `filter.d` |
| action | fail2ban's: what a ban does | `actions`, `action.d` |
| settings | the top-level files fail2ban reads after its own | `Settings` |
| file | one edited file, of a kind, by name | `File`, `Files` |
| stock | fail2ban's own configuration, as its package installed it | `Stock`, `StockDir` |
| composed | the directory fail2ban runs with, built from stock and the files | `Composer`, `Live` |
| logs | what the engine reads logs from: its read-only mounts and the jails' log directories | `LogPlaces`, `log-files` |
| ban | an address kept out by a jail, now or in the history | `Ban`, `bans` |
| version | a hash of a file's content, which a save is made against | `Version`, `VersionOf` |
| token | an API token: what a script or an agent sends to /api/v1 instead of the password | `Token`, `Tokens` |
| scope | what a token may do there: read, or read and write | `ScopeRead`, `ScopeWrite` |

**"User" is not a word here.** There is one password, and whoever has it is signed in.

## American spelling

`color`, `favorite`.

## Comments

**Why, never what.** A comment restating the line under it is noise. A comment recording the
reason a line is written the way it is stops somebody "simplifying" it back into a bug.

**No prose.** A sentence or two. An argument that needs three paragraphs belongs in `docs/`.

**No history.** Never "this used to be X". Git holds that.

**Say it once.** The same reason in a function, its test and its caller is three copies to keep
true.

## Docs

`docs/` holds the decisions, one file per subject. A heading states the decision and the text
under it gives the reason: `## A save is checked against everything, then written, then
reloaded`, not `## Saving`. A decision is written down in the change that makes it.

## Commits

**One or two lines.** A declarative sentence saying what the change accomplishes. Capitalized, no
trailing period, no prefix, no ticket number.

**No trailers. No `Co-Authored-By`. No generated-with footer.** Ever, whoever or whatever wrote
the change.

## Go

- `gofmt` clean.
- Tests beside sources as `*_test.go`, named as sentences:
  `TestARefusedSaveLeavesTheDiskAsItWas`.
- Errors wrap with `%w` and name what was being done.
- One error vocabulary in `internal/engine` — `ErrInvalid`, `ErrNotFound`, `ErrConflict` — with a
  sentence for whoever reads it, mapped onto a status in one place.
- `internal/history` is the only package that reads fail2ban's database, and only reads it.
- `context.Context` first on anything that can block, and every wait bounded.

## Interface

**Every add or change happens in a dialog or an editor that holds it until Save.** Save sends the
whole change at once; a refusal leaves everything as it was typed, with the server's sentence and
fail2ban's own lines. Leaving an editor with changes in it asks first.

A delete or an unban asks first, in the application's own dialog. A command whose label ends in
"…" opens a dialog; one without acts on the press.

## TypeScript

- Prettier, default settings. oxlint.
- Components are `PascalCase.tsx`; everything else is `camelCase.ts`.
- Imports use the `@app/*` alias, never `../../`.
- `strict`, `noUncheckedIndexedAccess`, `noUnusedLocals`, `noUnusedParameters`,
  `verbatimModuleSyntax`.

## Time

- `main.go` pins `time.Local = time.UTC`.
- The API speaks Unix seconds; the interface formats them in the browser's zone, and the days the
  history counts are UTC days.

## Logging

`log/slog`, one JSON object a line on stderr, beside fail2ban's own lines on stdout. Log what an
operator needs: a file saved or deleted, a ban or an unban by hand, a refused password and from
where, fail2ban stopping and starting.

**Never** a password, a cookie, or a request's query.
