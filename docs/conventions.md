# Conventions

These rules make queries both easy to read and safe for automation to pick up.

## 1. IDs and file names

Every query has a stable ID, `<DOMAIN>-<TYPE>-<NNN>`:

| Part | Values |
|------|--------|
| DOMAIN | `IDN` identity, `MAL` malware (add more later, e.g. `EML` email, `CLD` cloud) |
| TYPE | `INV` investigate, `HNT` hunt, `DET` detect |
| NNN | Sequential number, never reused |

File names are descriptive kebab-case (`signin-summary-for-user.kql`). The ID goes in the
header, not the file name, so a file can be renamed without breaking playbooks or automation
that reference the ID.

## 2. Header block (`.kql` files)

Every `.kql` file starts with a header of `// key: value` lines, one value per line. The header
ends at the first line that does not match `// key: value`. Free-form notes go after it.

```
// id:          IDN-INV-001
// name:        Sign-in summary for a user
// type:        investigate
// status:      stable
// platform:    sentinel
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
| `type` | `investigate`, `hunt`, or `function` |
| `status` | `draft` → `testing` → `stable`. Automation should only run `stable` |
| `platform` | `sentinel` (Log Analytics), `xdr` (Defender advanced hunting), or `both` |
| `requires` | Workspace functions from `functions/` that must be deployed first |
| `parameters` | The `let` variables a caller is expected to set |
| `entities` | Entity types in the output, for SOAR mapping |

Detections in `detect/` use the Sentinel analytic rule YAML schema instead. Put the library ID
in a `# library_id:` comment on the first line.

## 3. Parameters

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

Tuning thresholds (for example `MinDistinctUsers`) are also `let` parameters, but they come after
the standard ones.

## 4. Time column

This environment uses `TimeGenerated` in places where Microsoft's examples use `Timestamp`.

- Default to `TimeGenerated` and set `platform: sentinel`.
- If a query is written for Defender advanced hunting, use `Timestamp` and set `platform: xdr`.
- Do not mix the two columns in one query.

## 5. Schema normalisation

If more than one query needs the same join, union or type conversion, move it into `functions/`
as a workspace function. Example: `IdentitySignins` unions interactive and non-interactive
sign-ins and converts their string and dynamic columns to one shape. Queries then call
`IdentitySignins` rather than repeating that logic.

Deploy functions by saving the body as a workspace function (Logs → Save → Save as function),
using the file name as the function name.

## 6. Output shape

- **investigate**: one row per meaningful pivot (per IP, per device, per operation), ordered
  chronologically or by suspicion. Keep columns that a responder needs to make a decision.
- **hunt**: aggregated, with the most suspicious rows first (rarest first, highest count first).
  Include `FirstSeen` and `LastSeen`.
- **detect**: one row per alertable event, with columns for every entity mapping.
