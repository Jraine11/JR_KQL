# JR_KQL
KQL designed at supporting detection and threat capabilities within an organisation. Designed on a custom setup so incompatabilities may be found (e.g. timegenerated instead of timestamp in some places)

## Layout

The library is organised **by investigation domain first**, then **by how the query is used**.

```
functions/            Shared let-function snippets (master copies, embedded into queries)
identity/             Entra ID / AD / account-centric investigations
  investigate/        Entity-scoped pivots: "given this user / IP, show me ..."
  hunt/               Environment-wide sweeps run on demand
  detect/             Scheduled detections: KQL plus schedule, severity and entities in the header
malware/              Endpoint / malware investigations (same three sub-folders)
playbooks/            Ordered investigation runbooks that chain queries by ID
templates/            Starting points for new queries and detections
tools/validate.py     Checks headers, IDs, snippets, time filters and the private denylist
docs/conventions.md   Header format, parameter names, IDs, time columns, portability rules
local/                Private material (gitignored, never published)
```

Why this shape:

- **Domain first** matches how an investigation starts: an identity alert or a malware alert.
- **The usage split** matches how each query runs. `investigate/` queries take an entity and
  are run by an analyst or by SOAR enrichment. `hunt/` queries sweep the whole estate.
  `detect/` queries run on a schedule. Each type has different needs for parameters,
  performance and output shape.
- **Every query is self-contained, standard-schema KQL.** It doesn't depend on saved functions or
  platform features, so it runs unchanged in any environment that has the tables, and a query
  ID plus parameters is enough to hand an investigation to another team.
- **Shared logic lives in `functions/` as a master copy.** Queries embed that copy, and the
  validator keeps the embedded copies identical to it.

## Index

| ID | Type | Query |
|----|------|-------|
| IDN-INV-001 | investigate | [Sign-in summary for a user](identity/investigate/signin-summary-for-user.kql) |
| IDN-INV-002 | investigate | [Account changes for a user](identity/investigate/account-changes-for-user.kql) |
| IDN-INV-003 | investigate | [Sign-ins from an IP](identity/investigate/signins-from-ip.kql) |
| IDN-INV-004 | investigate | [Session reuse across networks for a user](identity/investigate/session-reuse-for-user.kql) |
| IDN-INV-005 | investigate | [Mailbox rules, forwarding and permissions for a user](identity/investigate/mailbox-rules-and-forwarding-for-user.kql) |
| IDN-HNT-001 | hunt | [Password spray by source IP](identity/hunt/password-spray-by-source-ip.kql) |
| IDN-HNT-002 | hunt | [MFA fatigue: repeated denials, then approval](identity/hunt/mfa-fatigue.kql) |
| IDN-DET-001 | detect | [Privileged role assigned outside PIM](identity/detect/privileged-role-assigned-outside-pim.kql) |
| MAL-INV-001 | investigate | [Device process activity around a time](malware/investigate/device-process-activity-around-time.kql) |
| MAL-INV-002 | investigate | [Hash prevalence](malware/investigate/hash-prevalence.kql) |
| MAL-INV-003 | investigate | [Device network activity around a time](malware/investigate/device-network-activity-around-time.kql) |
| MAL-INV-004 | investigate | [Device persistence changes around a time](malware/investigate/device-persistence-around-time.kql) |
| MAL-INV-005 | investigate | [File origin for a hash](malware/investigate/file-origin.kql) |
| MAL-INV-006 | investigate | [Alert entities and next steps](malware/investigate/alert-entities.kql) |
| MAL-HNT-001 | hunt | [Encoded PowerShell (decoded, rarest first)](malware/hunt/encoded-powershell.kql) |
| MAL-DET-001 | detect | [Office app spawning a script interpreter / LOLBin](malware/detect/office-app-spawning-interpreter.kql) |
| FN-IDN-001 | snippet | [IdentitySignins](functions/IdentitySignins.kql) |

Playbooks: [Compromised account triage](playbooks/compromised-account-triage.md) ·
[Malware alert triage](playbooks/malware-alert-triage.md)

## Backlog

Candidates to fill out the identity and malware areas next.

**Identity**
- New MFA method registered shortly after a risky or unfamiliar sign-in (detection)
- Risk events and risky-user history for a user (`AADUserRiskEvents`, `AADRiskyUsers`)
- UEBA anomalies for a user (`BehaviorAnalytics`)
- OAuth app consent with high-risk permissions (`AuditLogs`)
- Service principal sign-ins from new IPs (`AADServicePrincipalSignInLogs`)
- On-prem: Kerberoasting, AS-REP roasting, LDAP recon and DCSync (`IdentityLogonEvents`,
  `IdentityQueryEvents`, `IdentityDirectoryEvents`, `SecurityEvent`)
- Legacy auth usage by user

**Malware**
- Unsigned or rarely signed binaries executed from user-writable paths (`DeviceFileCertificateInfo`)
- LOLBin downloads (certutil, bitsadmin, curl, mshta with URLs)
- Rare processes making outbound connections
- AV detections that were not remediated (`DeviceEvents`)

## Contributing

Start from a file in `templates/`, follow [docs/conventions.md](docs/conventions.md), and run
`python3 tools/validate.py` before committing.
