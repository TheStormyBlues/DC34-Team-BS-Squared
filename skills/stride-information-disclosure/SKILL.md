---
name: stride-information-disclosure
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Information Disclosure threats — any way credentials, tokens, or account details could leak to someone not entitled to them. Applies to processes, data stores, and data flows."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "I"
---

# STRIDE — Information Disclosure (Authentication Scope)

## Overview

Information Disclosure violates **confidentiality**: data reaches someone not authorized to
have it. In an authentication use case the sensitive data is narrow and high-value —
passwords and their hashes, session tokens and JWTs, reset tokens, MFA secrets and recovery
codes, signing keys, and the existence of an account itself.

Two categories deserve equal weight and are often treated unequally:

- **Direct leakage** — a secret is stored weakly, transmitted in the clear, written to a log,
  or returned in a response.
- **Inferential leakage** — the system reveals *whether* something is true. Account
  enumeration is the canonical case: no secret is disclosed, yet an attacker learns which
  addresses are registered, which turns an untargeted attack into a targeted one.

## Elements this letter applies to

| Element type | Ask |
|---|---|
| Process | What does this process return, log, or error with? Does its behaviour differ observably? |
| Data store | How is the secret stored at rest, and who can read it? |
| Data flow | Is this flow encrypted, and does it carry more than the receiver needs? |

Do not raise Information Disclosure against external entities. If the DFD has no processes,
data stores, or data flows, return an empty `threats` array.

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

### Scenario 1: Account enumeration through differential responses
Registration says "email already in use", or login distinguishes "no such account" from
"wrong password", or password reset says "we don't recognise that address". The attacker
harvests valid accounts, then attacks only those.

### Scenario 2: Enumeration through timing
Responses are indistinguishable in content, but the code returns early for an unknown
account and runs an expensive password hash for a known one. The timing difference is the
oracle.

### Scenario 3: Passwords recoverable from the store
Passwords are stored in plaintext, encoded rather than hashed, or hashed with a fast
unsalted algorithm such as MD5 or SHA-1. A single database read compromises every account —
and, given password reuse, accounts on other systems.

### Scenario 4: Secrets committed to the repository
A JWT signing key, database password, or API credential is present in source control.
Anyone who can read the repository — including, for an open-source target, everyone — can
mint tokens or read the credential store directly.

### Scenario 5: Tokens leaked through the browser
A session token or reset token is placed in a URL query string. It is then written to server
logs, browser history, and the `Referer` header sent to third-party sites. Storing a JWT in
`localStorage` similarly exposes it to any successful XSS.

### Scenario 6: Verbose failure output
A stack trace, database error, or debug endpoint reveals schema, file paths, library
versions, or query text — each of which sharpens a subsequent attack.

## Vulnerable Patterns to Detect

### Pattern 1: Fast or unsalted password hashing
```javascript
// VULNERABLE: MD5 is fast and unsalted — a commodity GPU recovers common passwords in seconds
const hash = crypto.createHash('md5').update(password).digest('hex')

// VULNERABLE: SHA-1, SHA-256 and friends are equally unsuitable as password KDFs
const hash = crypto.createHash('sha256').update(password).digest('hex')
```

### Pattern 2: Distinguishable responses across the account lifecycle
```javascript
// VULNERABLE: three different oracles for account existence
if (!user) return res.status(404).json({ error: 'No account with that email' })
if (await User.count({ where: { email } })) return res.status(409).json({ error: 'Email already registered' })
if (!found) return res.json({ message: 'That address is not in our system' })
```

### Pattern 3: Timing oracle from an early return
```javascript
// VULNERABLE: unknown account returns fast, known account pays for bcrypt
const user = await User.findOne({ where: { email } })
if (!user) return res.status(401).json({ error: 'Invalid email or password' })
const ok = await bcrypt.compare(password, user.password)   // ~100ms, only for real accounts
```

### Pattern 4: Secret in source
```javascript
// VULNERABLE: anyone with the repo can sign a token for any user
const JWT_SECRET = 'supersecret123'
```

### Pattern 5: Over-returning the user object
```javascript
// VULNERABLE: serializes password hash, reset token, MFA secret, internal flags
res.json(await User.findByPk(req.params.id))
```

### Pattern 6: Token in a URL, or in web storage
```javascript
// VULNERABLE: lands in access logs, browser history, and the Referer header
res.redirect(`/reset?token=${resetToken}`)

// VULNERABLE: readable by any script that achieves XSS
localStorage.setItem('token', jwt)
```

### Pattern 7: Debug output reaching the client
```javascript
// VULNERABLE: leaks stack, query, and file paths
app.use((err, req, res, next) => res.status(500).json({ error: err.stack }))
```

## Secure Patterns (what a mitigation looks like)

```javascript
// A real password KDF with a work factor, salted per user
const hash = await bcrypt.hash(password, 12)      // or argon2id / scrypt

// One response for every authentication outcome
return res.status(401).json({ error: 'Invalid email or password' })

// Neutral response for registration and reset, regardless of existence
return res.json({ message: 'If that address is registered, we have sent an email.' })

// Equalize work so timing carries no signal
const record = user ?? DUMMY_USER
const ok = await bcrypt.compare(password, record.password) && user !== null

// Secrets from the environment, never from source
const JWT_SECRET = process.env.JWT_SECRET

// Serialize an explicit allow-list
res.json({ id: user.id, email: user.email, createdAt: user.createdAt })

// Token in the POST body or an HttpOnly cookie, never in the URL
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' })

// Generic error to the client, detail to the log only
app.use((err, req, res, next) => {
  logger.error({ err, requestId: req.id })
  res.status(500).json({ error: 'Internal server error', requestId: req.id })
})
```

## Analysis Checklist

For each process, data store, and data flow in the DFD:

1. **Password storage** — which algorithm, what work factor, salted per user? Name the file.
   Anything from the SHA family used directly is a finding.
2. **Enumeration by content** — do login, registration, password reset, and MFA enrollment
   ever respond differently for a known versus unknown account? Check status codes and
   headers, not just message bodies.
3. **Enumeration by timing** — is there an early return before the expensive comparison?
4. **Response shape** — does any endpoint serialize a whole user record? List the fields that
   escape.
5. **Secrets in the repository** — grep for signing keys, connection strings, API keys, and
   committed `.env` files.
6. **Token placement** — do tokens appear in URLs, `localStorage`, or non-`HttpOnly` cookies?
7. **Transport** — is HTTPS enforced end to end? Is HSTS set? Do internal flows between
   processes cross a network unencrypted?
8. **Logs** — are passwords, tokens, reset links, or full request bodies written? Coordinate
   with Repudiation, which raises the same pattern from the integrity side.
9. **Caching** — do authenticated responses set `Cache-Control: no-store`?
10. **CORS** — is `Access-Control-Allow-Origin` a wildcard or reflected, while credentials are
    allowed?

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "I",
  "threats": [
    {
      "id": "T-<use_case_id>-I-001",
      "stride": "I",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "User Credential Store", "type": "data_store" },
      "trust_boundary": "Application Server → Database",
      "description": "What the threat is, against this specific element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "models/user.ts", "line": 31, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "medium",
      "impact": "high",
      "risk": "high",
      "confidence": "high",
      "cwe": ["CWE-916"],
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
not. Never reproduce a real secret you find in the source — cite its file and line and
describe it, but put a redacted placeholder in the `snippet` field. If an element has no
credible Information Disclosure threat, omit it rather than padding.

## References

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-204: Observable Response Discrepancy
- CWE-208: Observable Timing Discrepancy
- CWE-256: Plaintext Storage of a Password
- CWE-257: Storing Passwords in a Recoverable Format
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-522: Insufficiently Protected Credentials
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-598: Use of GET Request Method With Sensitive Query Strings
- CWE-798: Use of Hard-coded Credentials
- CWE-916: Use of Password Hash With Insufficient Computational Effort
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
