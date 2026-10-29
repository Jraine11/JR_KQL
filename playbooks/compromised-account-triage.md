# Compromised account triage

**Trigger:** risky sign-in alert, user report, password spray hit (IDN-HNT-001), MFA fatigue hit (IDN-HNT-002), or an IOC IP.
**Inputs:** `TargetUPN`, and optionally `TargetIP`.

| Step | Query | Question | Escalate if |
|------|-------|----------|-------------|
| 1 | IDN-INV-001 | Where has this user signed in from? | IP/ASN/country not seen in the baseline with a successful sign-in, or failures followed by success from a new IP |
| 2 | IDN-INV-003 | Who else used the suspicious IP from step 1? | Other users succeeded from the same IP, which means wider scope |
| 3 | IDN-INV-002 | Did anyone change the account after the suspicious sign-in? | MFA method added/changed, password reset, role or app consent from the suspicious IP |
| 4 | IDN-INV-004 | Was a session token replayed from another network? | Same session used from a second country, or from a hosting/VPN ASN mid-session |
| 5 | IDN-INV-005 | Did the attacker set up mailbox persistence? | Inbox rule that forwards, deletes or hides mail, mailbox forwarding, or new delegate permissions, especially from a suspicious IP |

**Containment checkpoint:** if step 1 shows a confirmed malicious success, or step 3 shows a
persistence change, revoke sessions, reset credentials and remove the new MFA methods before you continue scoping.

**Automation mapping:** steps 1 to 5 need only `TargetUPN` / `TargetIP`, so a SOAR playbook can
run them on incident creation and add the results as incident comments.

**Data you cannot access:** every query is self-contained, so if part of the data sits in a store you
cannot query, send its owners the query ID and parameters and ask them to run it there.
