# Compromised account triage

**Trigger:** risky sign-in alert, user report, password spray hit (IDN-HNT-001), or an IOC IP.
**Inputs:** `TargetUPN`, and optionally `TargetIP`.

| Step | Query | Question | Escalate if |
|------|-------|----------|-------------|
| 1 | IDN-INV-001 | Where has this user signed in from? | IP/ASN/country not seen in the baseline with a successful sign-in, or failures followed by success from a new IP |
| 2 | IDN-INV-003 | Who else used the suspicious IP from step 1? | Other users succeeded from the same IP, which means wider scope |
| 3 | IDN-INV-002 | Did anyone change the account after the suspicious sign-in? | MFA method added/changed, password reset, role or app consent from the suspicious IP |
| 4 | *(backlog)* | Token replay / session reuse | Same session used from more than one IP or ASN |
| 5 | *(backlog)* | Mailbox persistence | New inbox rule or forwarding after the suspicious sign-in |

**Containment checkpoint:** if step 1 shows a confirmed malicious success, or step 3 shows a
persistence change, revoke sessions, reset credentials and remove the new MFA methods before you continue scoping.

**Automation mapping:** steps 1 to 3 need only `TargetUPN` / `TargetIP`, so a SOAR playbook can
run them on incident creation and add the results as incident comments.
