---
name: stride-tampering
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Tampering threats — any way an attacker could modify credentials, tokens, session state, or user records in transit or at rest. Applies to processes, data stores, and data flows."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "T"
---

# STRIDE — Tampering (Authentication Scope)

## Overview

Tampering violates **integrity**: an attacker modifies data or code that the system later
trusts. In an authentication use case the tampering targets are the credential store, the
session or token that carries identity, and the fields of a user record that decide who
someone is.

The distinction from Spoofing is worth holding: Spoofing is *becoming* another principal by
defeating the check; Tampering is *changing the data the check reads*. A forged JWT
signature is Spoofing. A JWT whose payload is editable because nothing verifies it is
Tampering that produces a spoof — raise it here and let the merge stage carry both.

## Elements this letter applies to

| Element type | Ask |
|---|---|
| Process | Does this process accept input that changes identity or authorization state? |
| Data store | Can the stored credential, session, or user record be modified out of band? |
| Data flow | Is this flow integrity-protected in transit, or can it be modified en route? |

Do not raise Tampering against external entities — you cannot tamper with a user, only with
what they send. If the DFD has no processes, data stores, or data flows, return an empty
`threats` array.

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

### Scenario 1: Mass assignment on registration
The registration handler passes the whole request body into the model create call. The
attacker adds `"role": "admin"` and the field is written straight to the user record. The
authentication step later reads that field and grants administrative access.

### Scenario 2: Client-side session state accepted as truth
Identity is carried in a cookie the client can edit, and the server does not sign or verify
it. Changing `user=alice` to `user=admin` is the whole attack.

### Scenario 3: Password reset bound to a client-supplied identity
The reset endpoint takes both a token and an email/user id, and looks up the account from
the supplied identifier rather than from the token. An attacker holds a valid token for
their own account, swaps the identifier, and rewrites another user's password.

### Scenario 4: Missing CSRF protection on credential change
Changing a password or the account email is a state-changing request. Without an
anti-CSRF token or `SameSite` cookie policy, an attacker's page can make the victim's
browser perform it — tampering with the credential through the victim's own session.

### Scenario 5: Injection that rewrites the user record
An unparameterized `UPDATE` in a profile or password-change path lets an attacker alter rows
they do not own, including the password hash or role of another account.

### Scenario 6: Cleartext transport
Authentication traffic served over HTTP, or a cookie without the `Secure` attribute, is
modifiable by anyone on the path, not merely observable.

## Vulnerable Patterns to Detect

### Pattern 1: Whole request body written to the user model
```javascript
// VULNERABLE: attacker supplies role, isAdmin, or emailVerified
router.post('/register', async (req, res) => {
  const user = await User.create(req.body)
  res.json(user)
})
```

### Pattern 2: Identity in an unsigned cookie
```javascript
// VULNERABLE: no signature, no verification — the client owns this value
res.cookie('user', user.email)
// ... later ...
const currentUser = req.cookies.user
```

### Pattern 3: Reset flow trusting a supplied identifier
```javascript
// VULNERABLE: account comes from the body, not from the token
const { token, email, newPassword } = req.body
if (await isTokenValid(token)) {
  await User.update({ password: hash(newPassword) }, { where: { email } })
}
```

### Pattern 4: Credential change without CSRF protection
```javascript
// VULNERABLE: state-changing POST, cookie auth, no anti-CSRF token
router.post('/account/password', requireLogin, async (req, res) => {
  await req.user.update({ password: hash(req.body.newPassword) })
})
```

### Pattern 5: Unparameterized update in an account path
```javascript
// VULNERABLE: injection can widen the WHERE clause to other rows
db.query("UPDATE Users SET email = '" + req.body.email +
         "' WHERE id = " + req.params.id)
```

### Pattern 6: Cookie without integrity or transport protection
```javascript
// VULNERABLE: no secure, no signing, no sameSite
app.use(session({ secret: 'keyboard cat', cookie: { secure: false } }))
```

## Secure Patterns (what a mitigation looks like)

```javascript
// Allow-list the fields a client may set; never spread the body
const { email, password } = req.body
await User.create({ email, password: await bcrypt.hash(password, 12), role: 'customer' })

// Derive identity from the verified token, never from the request body
const account = await tokenToAccount(req.body.token)
await account.update({ password: await bcrypt.hash(newPassword, 12) })

// Sign session state and reject modified values
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' },
}))

// Parameterize every write in an account path
await User.update({ email }, { where: { id: req.user.id } })

// Require the current password before changing the credential
if (!await bcrypt.compare(req.body.currentPassword, req.user.password)) {
  return res.status(403).json({ error: 'Invalid email or password' })
}
```

## Analysis Checklist

For each process, data store, and data flow in the DFD:

1. **Field-level trust** — for every write to a user record, which fields come from the
   client? Is `role`, `isAdmin`, `emailVerified`, or equivalent among them?
2. **Where identity lives** — is it server-side session state, or a client-held value? If
   client-held, is it signed and is the signature verified on every read?
3. **Reset and recovery** — is the target account derived from the token, or from a
   parameter the attacker also controls?
4. **Re-authentication** — does changing a password, email, or MFA setting require the
   current credential?
5. **CSRF** — are state-changing authentication requests protected by a token or a strict
   `SameSite` policy?
6. **Query construction** — is any query in an account path built by concatenation?
7. **Transport** — is HTTPS enforced (HSTS, redirect), and do cookies carry `Secure`,
   `HttpOnly`, and `SameSite`?
8. **Store-level access** — could the credential store be written by a path that bypasses
   the application, such as an admin interface, a migration, or a seed script?

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "T",
  "threats": [
    {
      "id": "T-<use_case_id>-T-001",
      "stride": "T",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "Registration Handler", "type": "process" },
      "trust_boundary": "Internet → Application Server",
      "description": "What the threat is, against this specific element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "routes/register.ts", "line": 18, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "high",
      "impact": "high",
      "risk": "critical",
      "confidence": "high",
      "cwe": ["CWE-915"],
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
not. If an element has no credible Tampering threat, omit it rather than padding.

## References

- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-565: Reliance on Cookies without Validation and Integrity Checking
- CWE-352: Cross-Site Request Forgery
- CWE-89: SQL Injection
- CWE-620: Unverified Password Change
- CWE-640: Weak Password Recovery Mechanism
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-494: Download of Code Without Integrity Check
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
