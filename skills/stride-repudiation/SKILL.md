---
name: stride-repudiation
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Repudiation threats — any way a user or attacker could deny performing an authentication action because the system cannot prove otherwise. Applies to processes and data stores."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "R"
---

# STRIDE — Repudiation (Authentication Scope)

## Overview

Repudiation violates **non-repudiation**: a party can plausibly deny having performed an
action, because the system produced no trustworthy record of it. In authentication this is
about whether the application can answer, after the fact, "who logged in, from where, when,
and what did they change about their own account?"

Repudiation is the letter analysts skip, because the finding is an *absence* rather than a
vulnerable line of code. Resist that. A login flow with no audit trail is a real finding: it
is why breaches go undetected for months, and it is the reason incident response cannot
distinguish a compromised account from a dishonest user. **Search for the logging that should
exist and record its absence with the same rigour you would apply to a present-but-broken
control.**

## Elements this letter applies to

| Element type | Ask |
|---|---|
| Process | Does this process produce a durable, attributable record of what it did? |
| Data store | Is the log or audit store itself protected from modification and deletion? |

Do not raise Repudiation against external entities or data flows. If the DFD has no
processes or data stores, return an empty `threats` array.

## Security-relevant authentication events

Every one of these should produce a log entry. Check each against the code and record the
ones that do not:

- Login success, and login failure (with the reason category, not the password)
- Logout, and session invalidation
- Account lockout, and lockout release
- Password change, and password reset request and completion
- Email or username change
- MFA enrollment, MFA removal, and recovery-code use
- Role or permission change
- Token issuance and revocation
- Account creation and deletion
- Administrative impersonation or "log in as user" features

## Attack Scenarios

### Scenario 1: Unattributable account takeover
An attacker authenticates with stolen credentials, changes the account email, and drains the
account. With no log of the login or the email change, the operator cannot establish whether
the legitimate user did this themselves, and cannot determine when access began.

### Scenario 2: Brute force invisible to detection
Failed authentication attempts are not logged. There is therefore nothing for monitoring to
alert on and nothing after the fact showing thousands of attempts preceded the successful
login.

### Scenario 3: Log injection destroying the record's integrity
The username is written into a line-oriented log without encoding. An attacker registers a
username containing a newline and a forged log line, and can then write arbitrary entries —
manufacturing an alibi or burying real activity.

### Scenario 4: Shared identity defeats attribution
Administrative actions run under a single service or shared account. The log shows what
happened but not which human did it, so any of them can deny it.

### Scenario 5: Mutable or short-lived logs
The application account has write access to its own audit table, or logs rotate after hours.
An attacker with application-level access deletes the evidence, or simply waits.

### Scenario 6: Missing or untrusted time
Entries carry no timestamp, use local time without a zone, or take the time from a
client-supplied header — so events cannot be ordered or correlated.

## Vulnerable Patterns to Detect

### Pattern 1: Authentication outcome with no record
```javascript
// VULNERABLE: neither branch is logged
router.post('/login', async (req, res) => {
  const user = await authenticate(req.body)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  res.json({ token: sign(user) })
})
```

### Pattern 2: Credential change with no record
```javascript
// VULNERABLE: the most security-relevant action in the app leaves no trace
router.post('/account/password', requireLogin, async (req, res) => {
  await req.user.update({ password: await hash(req.body.newPassword) })
  res.json({ ok: true })
})
```

### Pattern 3: Log entry missing the attributes that make it useful
```javascript
// VULNERABLE: no user id, no source address, no timestamp, no outcome
console.log('login attempt')
```

### Pattern 4: Unencoded user input in a log line
```javascript
// VULNERABLE: a username containing \n forges subsequent log lines
logger.info('Failed login for ' + req.body.email)
```

### Pattern 5: Secrets written into the log
```javascript
// VULNERABLE: turns the log into a credential store — also an Information Disclosure finding
logger.debug('login payload', req.body)
```

### Pattern 6: Application owns its own audit trail
```javascript
// VULNERABLE: the same credential that writes can delete
await AuditLog.destroy({ where: { userId: req.user.id } })
```

## Secure Patterns (what a mitigation looks like)

```javascript
// Log both outcomes, with the attributes that make an entry actionable
logger.info({
  event: 'auth.login',
  outcome: success ? 'success' : 'failure',
  reason: success ? undefined : 'bad_credentials',   // category, never the password
  userId: user?.id ?? null,
  email: redact(req.body.email),
  sourceIp: req.ip,
  userAgent: req.get('user-agent'),
  timestamp: new Date().toISOString(),               // UTC, server clock
  requestId: req.id,
})

// Structured logging encodes the fields — no line injection surface
logger.info({ event: 'auth.password_change', userId: req.user.id, sourceIp: req.ip })

// Ship to an append-only sink the application cannot rewrite
auditSink.append(entry)   // write-only credential, separate retention policy
```

## Analysis Checklist

For each process and data store in the DFD:

1. **Event coverage** — walk the event list above and mark each present or absent. Absence is
   the finding.
2. **Both outcomes** — are failures logged as well as successes? Failure-only monitoring
   misses the successful takeover; success-only misses the brute force.
3. **Attribution fields** — does each entry carry user identity, source address, timestamp,
   and a request or session correlator?
4. **Time** — is the timestamp server-generated, UTC, and consistently formatted?
5. **Injection** — is user-controlled text encoded, or concatenated into a line-oriented log?
6. **Secrets in logs** — are passwords, tokens, reset links, or full request bodies logged?
   Raise it here and expect Information Disclosure to raise it too.
7. **Log integrity** — can the application credential modify or delete its own audit records?
   Is the store append-only, off-host, or otherwise out of reach?
8. **Retention** — is the trail kept long enough to investigate a breach discovered months
   later?
9. **Shared identity** — do any privileged actions run under an account shared by multiple
   humans?

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "R",
  "threats": [
    {
      "id": "T-<use_case_id>-R-001",
      "stride": "R",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "Login Handler", "type": "process" },
      "trust_boundary": "Internet → Application Server",
      "description": "What the threat is, against this specific element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "routes/login.ts", "line": 55, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "high",
      "impact": "medium",
      "risk": "high",
      "confidence": "high",
      "cwe": ["CWE-778"],
      "recommendation": "Concrete fix."
    }
  ]
}
```

**Derive `risk` from this matrix — do not assign it independently:**

| | Impact High | Impact Medium | Impact Low |
|---|---|---|---|
| **Likelihood High** | Critical | High | Medium |
| **Likelihood Medium** | High | Medium | Low |
| **Likelihood Low** | Medium | Low | Low |

**Rules.** Number IDs from 001 within this call. `status` is one of `unmitigated`,
`partial`, `mitigated` — keep mitigated threats, they demonstrate which controls exist.
`confidence` is `high` only when `evidence` cites a real file and line; use `medium` for an
inference drawn from code you read, `low` when the threat applies by element type but you
found no supporting code.

**Evidence for an absence.** When the finding is missing logging, cite the handler where the
log call *should* be — the file and line of the code path that completes without recording
anything. That is legitimate `high` confidence evidence. Never fabricate a path: an empty
`evidence` array with `confidence: "low"` is correct when you could not locate the handler.
If an element has no credible Repudiation threat, omit it rather than padding.

## References

- CWE-778: Insufficient Logging
- CWE-223: Omission of Security-relevant Information
- CWE-117: Improper Output Neutralization for Logs
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-284: Improper Access Control (applied to the log store)
- CWE-1246: Improper Write Handling in Limited-write Non-Volatile Memories
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
