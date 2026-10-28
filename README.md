# JR_KQL
KQL designed at supporting detection and threat capabilities within an organisation. Designed on a custom setup so incompatabilities may be found (e.g. timegenerated instead of timestamp in some places)

## Layout

The library is organised **by investigation domain first**, then **by how the query is used**.

```
functions/            Shared workspace functions (schema normalisation lives here, nowhere else)
identity/             Entra ID / AD / account-centric investigations
  investigate/        Entity-scoped pivots: "given this user / IP, show me ..."
  hunt/               Environment-wide sweeps run on demand
  detect/             Scheduled analytic rules (Sentinel YAML), ready to deploy
malware/              Endpoint / malware investigations (same three sub-folders)
playbooks/            Ordered investigation runbooks that chain queries by ID
templates/            Starting points for new queries and detections
docs/conventions.md   Header format, parameter names, IDs, time columns
```

Why this shape:

- **Domain first** matches how an investigation starts: an identity alert or a malware alert.
- **The usage split** matches how each query runs. `investigate/` queries take an entity and
  are run by an analyst or by SOAR enrichment. `hunt/` queries sweep the whole estate.
  `detect/` rules run on a schedule and create incidents. Each type has different needs for
  parameters, performance and output shape.
- **`functions/`** keeps the custom-schema differences (time column, string vs dynamic fields,
  interactive vs non-interactive sign-ins) in one place. When the schema changes, only the
  function changes.
- **Playbooks** reference queries by stable ID, so manual runbooks and automation both point
  at the same source of truth.

## Index

| ID | Type | Query |
|----|------|-------|
| IDN-INV-001 | investigate | [Sign-in summary for a user](identity/investigate/signin-summary-for-user.kql) |
| IDN-INV-002 | investigate | [Account changes for a user](identity/investigate/account-changes-for-user.kql) |
| IDN-INV-003 | investigate | [Sign-ins from an IP](identity/investigate/signins-from-ip.kql) |
| IDN-HNT-001 | hunt | [Password spray by source IP](identity/hunt/password-spray-by-source-ip.kql) |
| IDN-DET-001 | detect | [Privileged role assigned outside PIM](identity/detect/privileged-role-assigned-outside-pim.yaml) |
| MAL-INV-001 | investigate | [Device process activity around a time](malware/investigate/device-process-activity-around-time.kql) |
| MAL-INV-002 | investigate | [Hash prevalence](malware/investigate/hash-prevalence.kql) |
| MAL-HNT-001 | hunt | [Encoded PowerShell (decoded, rarest first)](malware/hunt/encoded-powershell.kql) |
| MAL-DET-001 | detect | [Office app spawning a script interpreter / LOLBin](malware/detect/office-app-spawning-interpreter.yaml) |

Playbooks: [Compromised account triage](playbooks/compromised-account-triage.md) ·
[Malware alert triage](playbooks/malware-alert-triage.md)

## Backlog

Candidates to fill out the identity and malware areas next.

**Identity**
- MFA fatigue / repeated MFA denials (`500121`) followed by success
- Token replay / AiTM indicators (same `SessionId` across IPs or ASNs)
- New MFA method registered shortly after a risky or unfamiliar sign-in (detection)
- OAuth app consent with high-risk permissions
- Inbox rule creation / mail forwarding following a suspicious sign-in
- On-prem: Kerberoasting (4769 RC4), AS-REP roasting, DCSync (4662 replication GUIDs)
- Legacy auth usage by user

**Malware**
- Network connections for a device around a time (MAL-INV)
- Persistence sweep: Run keys, services, scheduled tasks, WMI subscriptions on a device
- File / process lineage for a hash: who dropped it and from where (download URL, email, USB)
- LOLBin downloads (certutil, bitsadmin, curl, mshta with URLs)
- Rare processes making outbound connections
- Defender AV detections that were not remediated
