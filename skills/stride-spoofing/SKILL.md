---
name: stride-spoofing
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Spoofing threats — any way an attacker could impersonate a legitimate user, service, or session. Applies to external entities and processes."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "S"
---

# STRIDE — Spoofing (Authentication Scope)

## Overview

Spoofing violates **authenticity**: an attacker successfully claims to be someone or
something they are not. In an authentication use case this is the primary threat class,
because authentication *is* the control that spoofing defeats.

Spoofing covers impersonating a **human principal** (logging in as another user), a
**session** (replaying or forging a token), or a **service** (a client trusting an
unauthenticated upstream).

## Elements this letter applies to

Iterate **only** these element types from the supplied DFD:

| Element type | Ask |
|---|---|
| External entity | How does the system prove this entity is who it claims? What could forge that proof? |
| Process | Does this process authenticate its callers? Does it authenticate the services it calls? |

Do not raise Spoofing threats against data stores or data flows — those belong to Tampering
and Information Disclosure. If the DFD has no external entities or processes, return an
empty `threats` array rather than inventing an element.

### Reading the diagram

The DFD is a Mermaid flowchart. Element types come from node shape:

| Element type | Shape | Example |
|---|---|---|
| External entity | rectangle | `CUST[Customer]` |
| Process | rounded | `LOGIN(Login Handler)` |
| Data store | cylinder | `USERS[(User Table)]` |
| Data flow | labelled arrow between two nodes | see the diagram |
| Trust boundary | `subgraph ... end` | `subgraph TB[Internet -> Application Server]` |

You are given a typed element inventory extracted from that diagram, printed above the
diagram itself. **Treat the inventory as the authoritative list of elements and their
types.** Do not re-derive a type from the diagram text, and do not raise a threat against
an element whose type is not in the applicability table at the top of this section.

## Attack Scenarios

### Scenario 1: Credential stuffing against an unthrottled login
An attacker replays a breach corpus of email/password pairs against `POST /login`. With no
rate limit, lockout, or CAPTCHA, a few thousand requests yield working accounts. The
authentication logic is *correct* — it is the absence of a control around it that permits
the spoof.

### Scenario 2: Forged session token
The application signs JWTs with a weak or hardcoded secret, or verifies them with a library
call that accepts the `alg` header from the token itself. The attacker mints a token with
`{"sub": "admin@juice-sh.op"}` and is authenticated without ever knowing a password.

### Scenario 3: Session fixation
The application accepts a session identifier supplied by the client and does not rotate it
on successful login. An attacker plants a known session ID in the victim's browser, waits
for them to authenticate, and then uses the same ID.

### Scenario 4: Password reset as an authentication bypass
The reset flow issues a token that is short, sequential, derived from a timestamp, or not
bound to the requesting account. Guessing or requesting the token for another user's account
is a direct path to impersonating them.

### Scenario 5: User enumeration narrowing the attack
Distinct responses for "no such user" and "wrong password" turn an unbounded credential
guess into a targeted one. Enumeration is an Information Disclosure finding in its own
right, but raise it here too when it materially enables a spoof.

## Vulnerable Patterns to Detect

### Pattern 1: JWT verified without pinning the algorithm
```javascript
// VULNERABLE: trusts the alg header inside the token
jwt.verify(token, publicKey, (err, decoded) => { ... })

// VULNERABLE: decode does not verify at all
const user = jwt.decode(token)
```

### Pattern 2: Hardcoded or weak signing secret
```javascript
// VULNERABLE: secret is in source control, so anyone with the repo can mint tokens
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIB...'
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' })
```

### Pattern 3: Login with no throttling or lockout
```javascript
// VULNERABLE: unbounded guessing, no counter, no delay, no captcha
router.post('/login', async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } })
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    return res.json({ token: sign(user) })
  }
  res.status(401).json({ error: 'Invalid credentials' })
})
```

### Pattern 4: Query built by concatenation in the login path
```javascript
// VULNERABLE: authentication bypass via injection — ' OR 1=1--
const q = "SELECT * FROM Users WHERE email = '" + req.body.email +
          "' AND password = '" + hash(req.body.password) + "'"
db.query(q)
```

### Pattern 5: Session identifier not rotated on privilege change
```javascript
// VULNERABLE: same session id before and after authentication
req.session.userId = user.id
res.redirect('/dashboard')   // no req.session.regenerate()
```

### Pattern 6: Distinguishable authentication failures
```javascript
// VULNERABLE: two different responses enable enumeration
if (!user) return res.status(404).json({ error: 'Account not found' })
if (!valid) return res.status(401).json({ error: 'Wrong password' })
```

## Secure Patterns (what a mitigation looks like)

```javascript
// Pin the algorithm and the key; never trust the token's own alg header
jwt.verify(token, publicKey, { algorithms: ['RS256'] })

// Load signing material from the environment, never from source
const privateKey = process.env.JWT_PRIVATE_KEY

// Throttle by both account and source address
router.post('/login', rateLimit({ windowMs: 15 * 60_000, max: 5 }), handler)

// Parameterize — no string building in an authentication query
await User.findOne({ where: { email: req.body.email } })

// Rotate the session on authentication
req.session.regenerate(() => { req.session.userId = user.id })

// One indistinguishable failure response, one constant-time comparison
return res.status(401).json({ error: 'Invalid email or password' })
```

## Analysis Checklist

For each external entity and process in the DFD:

1. **Proof of identity** — what credential, token, or certificate authenticates this entity?
2. **Strength of that proof** — password only, or a second factor? Is a password policy enforced?
3. **Guessing cost** — is there rate limiting, lockout, exponential backoff, or CAPTCHA on the
   authenticating process? Name the file that implements it, or record its absence.
4. **Token integrity** — is the algorithm pinned, the secret out of source control, the
   expiry short, the signature actually verified?
5. **Session lifecycle** — is the identifier rotated on login and invalidated on logout?
   Is it random enough to resist prediction?
6. **Alternate doors** — password reset, "remember me", OAuth callback, API key, and
   impersonation/support features are all authentication paths. Each is its own threat.
7. **Enumeration** — do responses, status codes, or timings differ between a known and an
   unknown account?
8. **Service-to-service** — when this process calls another, does the callee verify the
   caller, or does it trust the network?

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "S",
  "threats": [
    {
      "id": "T-<use_case_id>-S-001",
      "stride": "S",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "Login Handler", "type": "process" },
      "trust_boundary": "Internet → Application Server",
      "description": "What the threat is, against this specific element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "routes/login.ts", "line": 42, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "high",
      "impact": "high",
      "risk": "critical",
      "confidence": "high",
      "cwe": ["CWE-307"],
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
not. If an element has no credible Spoofing threat, omit it rather than padding.

## References

- CWE-287: Improper Authentication
- CWE-290: Authentication Bypass by Spoofing
- CWE-294: Authentication Bypass by Capture-replay
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements
- CWE-640: Weak Password Recovery Mechanism
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
