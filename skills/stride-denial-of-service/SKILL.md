---
name: stride-denial-of-service
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Denial of Service threats — any way an attacker could exhaust resources or lock legitimate users out of the authentication path. Applies to processes, data stores, and data flows."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "D"
---

# STRIDE — Denial of Service (Authentication Scope)

## Overview

Denial of Service violates **availability**: legitimate users cannot authenticate. In an
authentication use case there are two distinct shapes, and analysts routinely find only the
first:

- **Resource exhaustion** — the attacker consumes CPU, memory, connections, or an external
  quota until the service degrades. Authentication is unusually exposed here because a
  correctly-implemented password KDF is *deliberately expensive*, so every unauthenticated
  request costs the server far more than it costs the attacker.
- **Targeted lockout** — the attacker uses a legitimate security control against its owner.
  Where account lockout exists, repeatedly failing logins against a known address locks that
  user out. The control works exactly as designed, and that is the attack.

The second shape is the one that gets missed. Look for it explicitly: for every protective
threshold in the authentication path, ask who else can trigger it.

## Elements this letter applies to

| Element type | Ask |
|---|---|
| Process | What does one unauthenticated request cost this process, and what bounds the rate? |
| Data store | Can an attacker grow this store without limit, or exhaust its connections? |
| Data flow | Can this flow be saturated, or does it depend on an external service with a quota? |

Do not raise Denial of Service against external entities. If the DFD has no processes, data
stores, or data flows, return an empty `threats` array.

## Attack Scenarios

### Scenario 1: KDF amplification
Each login attempt runs bcrypt at cost factor 12 — roughly 100ms of CPU. An attacker sends
concurrent login requests with any password. A few hundred requests per second saturate the
CPU pool and the site stops responding to everyone, without a single valid credential.

### Scenario 2: Lockout as a weapon
The application locks an account after five failed attempts. An attacker with a list of
customer email addresses locks every one of them out, on a schedule. Support is overwhelmed
and users cannot reach the service.

### Scenario 3: Password-reset email flooding
The reset endpoint sends mail on every request with no per-account or global rate limit. An
attacker floods a victim's inbox, exhausts the transactional mail quota so genuine resets
stop being delivered, and gets the sending domain reputation-blocked.

### Scenario 4: Unbounded input reaching an expensive operation
No maximum password length is enforced. The attacker submits a multi-megabyte password;
hashing it consumes CPU and memory proportional to the input. The same shape appears when an
oversized JWT is passed to a verification routine.

### Scenario 5: Regular expression denial of service
Email or password validation uses a regex with nested quantifiers. A crafted input drives
catastrophic backtracking and pins a CPU core with a single request.

### Scenario 6: Session or token store growth
Every request to an unauthenticated endpoint creates a session record. The attacker makes
millions, and the session store fills the disk or evicts real users' sessions.

### Scenario 7: Connection pool exhaustion
Each login attempt takes a database connection and holds it across a slow operation. Under
a modest flood the pool is empty and every other feature that needs the database fails too.

## Vulnerable Patterns to Detect

### Pattern 1: No rate limiting on an expensive unauthenticated endpoint
```javascript
// VULNERABLE: unbounded, and each call costs ~100ms of CPU
router.post('/login', async (req, res) => {
  const ok = await bcrypt.compare(req.body.password, user.password)
  ...
})
```

### Pattern 2: Lockout with no compensating control
```javascript
// VULNERABLE: any attacker who knows an email can lock its owner out indefinitely
if (user.failedAttempts >= 5) {
  return res.status(423).json({ error: 'Account locked' })
}
```

### Pattern 3: Unbounded input length
```javascript
// VULNERABLE: no maximum — a huge password is hashed at the caller's request
const hash = await bcrypt.hash(req.body.password, 12)
```

### Pattern 4: Catastrophic backtracking in validation
```javascript
// VULNERABLE: nested quantifier, exponential on a crafted near-match
const EMAIL = /^([a-zA-Z0-9_\.\-]+)+@([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/
if (!EMAIL.test(req.body.email)) return res.status(400).end()
```

### Pattern 5: Unthrottled outbound side effect
```javascript
// VULNERABLE: one request, one email, no limit, external quota
router.post('/forgot-password', async (req, res) => {
  await mailer.send(resetEmail(req.body.email))
  res.json({ ok: true })
})
```

### Pattern 6: Session created for every anonymous visitor
```javascript
// VULNERABLE: saveUninitialized persists a row per request
app.use(session({ saveUninitialized: true, resave: true, store: dbStore }))
```

## Secure Patterns (what a mitigation looks like)

```javascript
// Layered limits: per source address and per account, on the expensive endpoint
router.post('/login',
  rateLimit({ windowMs: 15 * 60_000, max: 100, keyGenerator: r => r.ip }),
  rateLimit({ windowMs: 15 * 60_000, max: 5, keyGenerator: r => r.body.email }),
  handler)

// Prefer escalating delay over hard lockout, so an attacker cannot weaponize it
const delayMs = Math.min(2 ** user.failedAttempts * 100, 30_000)

// Bound input before it reaches anything expensive
if (typeof password !== 'string' || password.length > 128) {
  return res.status(400).json({ error: 'Invalid email or password' })
}

// Linear-time validation instead of a backtracking regex
if (!email.includes('@') || email.length > 254) return res.status(400).end()

// Rate limit the side effect as well as the endpoint, and respond identically either way
await resetLimiter.consume(email)   // per-account budget
return res.json({ message: 'If that address is registered, we have sent an email.' })

// Do not persist sessions for anonymous visitors
app.use(session({ saveUninitialized: false, resave: false }))
```

## Analysis Checklist

For each process, data store, and data flow in the DFD:

1. **Cost per request** — what is the most expensive operation an *unauthenticated* caller
   can trigger? Password hashing, token verification, and mail sending are the usual three.
2. **Rate limiting** — is there any? Name the file and the limit. Is it keyed by source
   address, by account, or both? An IP-only limit fails against a botnet; an account-only
   limit fails against spray.
3. **Lockout weaponization** — for every threshold that disables an account, who besides the
   owner can drive it? This is the finding most often missed — raise it explicitly.
4. **Input bounds** — is there a maximum length on password, email, and token fields *before*
   they reach an expensive routine?
5. **Regex safety** — do validation patterns contain nested quantifiers or overlapping
   alternation?
6. **External quotas** — does this path consume a metered third-party service (mail, SMS,
   CAPTCHA, an identity provider)? What happens when the quota is gone?
7. **Unbounded growth** — can an unauthenticated caller create rows in the session, token, or
   audit store?
8. **Connection and worker pools** — does an authentication request hold a scarce resource
   across a slow call?
9. **Recovery** — when the limit trips, does the response leak whether the account exists?
   That is an Information Disclosure finding riding on this control.

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "D",
  "threats": [
    {
      "id": "T-<use_case_id>-D-001",
      "stride": "D",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "Login Handler", "type": "process" },
      "trust_boundary": "Internet → Application Server",
      "description": "What the threat is, against this specific element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "routes/login.ts", "line": 12, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "high",
      "impact": "medium",
      "risk": "high",
      "confidence": "high",
      "cwe": ["CWE-770"],
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
found no supporting code. Never fabricate a file path or line number: an empty `evidence`
array with `confidence: "low"` is correct and expected, a plausible-looking invented path is
not. Describe attacks in terms of the resource consumed and the control that is missing — do
not write load-generation scripts or tooling. If an element has no credible Denial of Service
threat, omit it rather than padding.

## References

- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-645: Overly Restrictive Account Lockout Mechanism
- CWE-400: Uncontrolled Resource Consumption
- CWE-1333: Inefficient Regular Expression Complexity
- CWE-405: Asymmetric Resource Consumption (Amplification)
- CWE-799: Improper Control of Interaction Frequency
- https://owasp.org/Top10/A04_2021-Insecure_Design/
- https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
