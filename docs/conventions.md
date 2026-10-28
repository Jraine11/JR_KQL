# Conventions

These rules make queries easy to read, safe for automation to pick up, and runnable anywhere the
standard Microsoft security tables exist.

## 1. Portability

- Queries use the **standard table names and schemas** (`SigninLogs`, `AuditLogs`,
  `DeviceProcessEvents`, ...) and nothing else. They do not call saved functions, watchlists,
  parsers or other platform-specific features.
- **Every query is self-contained.** You can copy it into any environment with those tables and
  run it. Shared logic is embedded rather than referenced (see section 6).
- **One query reads one dataset.** If your data is split across several stores with the same
  schema, run the query in each store or through a layer that combines them. Add a column that
  shows which store each row came from. If you can't access a store, give its owners the query
  ID and parameters. Because each query is self-contained, they can run it unchanged.
- **The repository is public.** Keep environment details out of it: no store names, internal
  table names, tenant domains, real users, IPs or hashes. Use example values
  (`user@contoso.com`, `203.0.113.10`) as parameter defaults. Put private material in `local/`,
  which is gitignored.

## 2. IDs and file names

Every query has a stable ID, `<DOMAIN>-<TYPE>-<NNN>`:

| Part | Values |
|------|--------|
| DOMAIN | `IDN` identity, `MAL` malware, `FN` shared snippet (add more later, e.g. `EML` email) |
| TYPE | `INV` investigate, `HNT` hunt, `DET` detect |
| NNN | Sequential number, never reused |

File names are descriptive kebab-case (`signin-summary-for-user.kql`). The ID goes in the
header, not the file name, so a file can be renamed without breaking playbooks or automation
that reference the ID.

## 3. Header block

Every `.kql` file starts with a header of `// key: value` lines, one value per line. The header
ends at the first line that does not match `// key: value`. Free-form notes go after it.

```
// id:          IDN-INV-001
// name:        Sign-in summary for a user
// type:        investigate
// status:      stable
// time_column: TimeGenerated
// tables:      SigninLogs, AADNonInteractiveUserSignInLogs
// requires:    IdentitySignins
// parameters:  TargetUPN, StartTime, EndTime
// entities:    Account, IP
// mitre:       T1078.004
// author:      JR
// updated:     2026-10-28
//
// Notes: free text after a blank comment line.
```

| Key | Meaning |
|-----|---------|
| `type` | `investigate`, `hunt`, `detect`, or `snippet` |
| `status` | `draft` → `testing` → `stable`. Automation should only run `stable` |
| `time_column` | `TimeGenerated` or `Timestamp` (see section 5) |
| `requires` | Snippets from `functions/` embedded in this query |
| `parameters` | The `let` variables a caller is expected to set |
| `entities` | Entity types in the output. Detections use `Type=Column` pairs |

Detections also need:

| Key | Meaning |
|-----|---------|
| `severity` | `Informational`, `Low`, `Medium`, `High` |
| `frequency` | How often the scheduler runs it (`1h`, `15m`) |
| `tactics` | MITRE ATT&CK tactic names |

## 4. Parameters

Parameters are `let` statements at the very top of the query body, directly after the header.
Use **the same names everywhere**, so automation can substitute values without per-query logic:

| Name | Type | Used for |
|------|------|----------|
| `TargetUPN` | string | User principal name |
| `TargetIP` | string | Source IP address |
| `TargetDevice` | string | Device name (short name or FQDN) |
| `TargetSHA256` | string | File hash, lower-case |
| `StartTime` / `EndTime` | datetime | Range-based queries |
| `PivotTime` | datetime | Event-centred queries (an alert time) |
| `WindowBefore` / `WindowAfter` | timespan | Range around `PivotTime` |
| `Lookback` | timespan | Detections: how far back each scheduled run looks |

Tuning thresholds (for example `MinDistinctUsers`) are also `let` parameters, but they come after
the standard ones.

## 5. Time column and time filters

- Default to `TimeGenerated`. Use `Timestamp` only for a table where `TimeGenerated` is not
  available, and record it in `time_column`. Do not mix the two columns in one query.
- **Every query filters on time first.** Nothing else adds a time filter, and these tables are
  very large.
- **Detections** filter with `| where TimeGenerated > ago(Lookback)`. Set `Lookback` a little
  longer than `frequency` to allow for late-arriving data, and de-duplicate in the scheduler.

## 6. Shared snippets

When several queries need the same union, join or type conversion, write it once as a `let`
function in `functions/<Name>.kql`, between `// BEGIN <Name>` and `// END <Name>` markers. A query
that uses it lists `<Name>` in `requires` and contains an identical copy of that block.

- Edit only the master copy in `functions/`, then run `python3 tools/validate.py --sync`.
- Pass the time range into the snippet as parameters, so that each table is filtered before
  any union or conversion.
- Keep columns that callers filter on (for example `UserPrincipalName`) unchanged, so the
  filter can be applied early.

## 7. Output shape

- **investigate**: one row per meaningful pivot (per IP, per device, per operation), ordered
  chronologically or by suspicion. Keep columns that a responder needs to make a decision.
- **hunt**: aggregated, with the most suspicious rows first (rarest first, highest count first).
  Include `FirstSeen` and `LastSeen`.
- **detect**: one row per alertable event, with a column for every entity in `entities`.

## 8. Before committing

Run `python3 tools/validate.py`. It checks headers, parameters, unique IDs, snippet copies and
detection time filters. If `local/denylist.txt` exists, it also fails when a tracked file
contains any term from it, one term per line. Use it for internal names that must never be
published.
