---
name: stride-elevation-of-privilege
description: "Use this skill to analyze authentication data flow diagrams for STRIDE Elevation of Privilege threats — any way an attacker could gain rights beyond those granted to them, including taking over another account or reaching administrative function. Applies to processes."
license: MIT
metadata:
  author: BS-Squared
  version: "1.0"
  stride_letter: "E"
---

# STRIDE — Elevation of Privilege (Authentication Scope)

## Overview

Elevation of Privilege violates **authorization**: an actor obtains rights they were never
granted. Two directions matter, and both belong in an authentication threat model:

- **Horizontal** — acting as a *different* user at the same privilege level. Account takeover
  through a password reset flaw is elevation, not merely spoofing, because the attacker
  acquires that account's entitlements.
- **Vertical** — acting at a *higher* privilege level. Reaching an administrative function
  from a customer account is the archetype.

The boundary with Spoofing is worth stating so the two skills do not collide: Spoofing is
about defeating the proof of identity; Elevation is about what the system *grants* once an
identity is established, and about paths that skip the check entirely. When one flaw does
both — a reset flow that hands over an admin account — raise it in both and let the merge
stage carry the duplicate.

## Elements this letter applies to

| Element type | Ask |
|---|---|
| Process | Does this process enforce an authorization decision, and can that decision be bypassed or influenced by the caller? |

Classic STRIDE-per-element assigns Elevation of Privilege to processes only. Do not raise it
against external entities, data stores, or data flows — a store that can be modified to
confer privilege is a Tampering finding, and the resulting privilege gain is the Elevation
finding against the *process that reads it*. If the DFD has no processes, return an empty
`threats` array.

## Attack Scenarios

### Scenario 1: Role assigned by the client at registration
The registration handler writes the whole request body to the user record. The attacker
registers with `"role": "admin"` and is an administrator from first login. The
authentication step never malfunctions — it faithfully authenticates an account that should
never have existed.

### Scenario 2: Authorization claim trusted from the token
The application reads `role` out of a JWT and acts on it without re-checking against the
database. Combined with any signature weakness — or simply a stale token issued before a
demotion — the claim becomes the privilege.

### Scenario 3: Administrative endpoint protected only by obscurity
An admin route has no authorization decorator or middleware; it is merely not linked from
the UI. Forced browsing reaches it directly.

### Scenario 4: Password reset for an arbitrary account
The reset flow accepts an account identifier the attacker controls, or issues a guessable
token. Resetting the administrator's password is a complete privilege escalation.

### Scenario 5: Stale session after a privilege change
A user's role is revoked, but existing sessions or tokens continue to carry the old
entitlement until natural expiry. Long-lived tokens with no revocation list make this
indefinite.

### Scenario 6: Authorization checked at the wrong layer
Authentication is enforced by middleware, but the object-level decision — *may this user act
on this record?* — is never made. Any authenticated user reaches any record by identifier.

### Scenario 7: Identity collision through a secondary login path
An OAuth or SSO callback links accounts by email address without verifying the address. An
attacker registers a provider account with the victim's email and inherits their local
account.

## Vulnerable Patterns to Detect

### Pattern 1: Privilege field accepted from the client
```javascript
// VULNERABLE: role, isAdmin, or deluxeToken supplied by the caller
router.post('/register', async (req, res) => {
  const user = await User.create(req.body)
  res.json(user)
})
```

### Pattern 2: Authorization decided from an unverified claim
```javascript
// VULNERABLE: the claim is the authority; nothing re-checks the database
const payload = jwt.decode(req.headers.authorization.split(' ')[1])
if (payload.role === 'admin') return next()
```

### Pattern 3: Route with no authorization check
```javascript
// VULNERABLE: authentication middleware exists elsewhere, but this route is not covered
router.get('/admin/users', async (req, res) => {
  res.json(await User.findAll())
})
```

### Pattern 4: Authentication without object-level authorization
```javascript
// VULNERABLE: requireLogin proves *who*, but nothing proves *whose record this is*
router.get('/api/users/:id/profile', requireLogin, async (req, res) => {
  res.json(await User.findByPk(req.params.id))
})
```

### Pattern 5: Privilege derived from a mutable, non-authoritative source
```javascript
// VULNERABLE: header or cookie set by the client decides privilege
if (req.headers['x-user-role'] === 'admin') { ... }
```

### Pattern 6: No revocation path for issued tokens
```javascript
// VULNERABLE: 30-day token, no deny list — demotion or logout changes nothing
const token = jwt.sign({ sub: user.id, role: user.role }, key, { expiresIn: '30d' })
```

### Pattern 7: Account linking on an unverified attribute
```javascript
// VULNERABLE: provider email is trusted without checking it was verified upstream
let user = await User.findOne({ where: { email: profile.email } })
if (!user) user = await User.create({ email: profile.email })
return done(null, user)
```

## Secure Patterns (what a mitigation looks like)

```javascript
// Server assigns privilege; the client cannot express it
const { email, password } = req.body
await User.create({ email, password: await bcrypt.hash(password, 12), role: 'customer' })

// Verify the token, then resolve authority from the database, not the claim
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
const user = await User.findByPk(payload.sub)
if (!user?.isAdmin) return res.status(403).json({ error: 'Forbidden' })

// Deny by default at the router, then opt routes out explicitly
router.use(requireAuth)
router.use('/admin', requireRole('admin'))

// Object-level authorization, not merely authentication
const profile = await User.findOne({ where: { id: req.params.id, id: req.user.id } })
if (!profile) return res.status(403).json({ error: 'Forbidden' })

// Short-lived access tokens plus a revocation check
const token = jwt.sign({ sub: user.id }, key, { expiresIn: '15m' })
if (await revocationList.has(payload.jti)) return res.status(401).end()

// Only link accounts on a provider-verified address
if (!profile.email_verified) return done(null, false)
```

## Analysis Checklist

For each process in the DFD:

1. **Who assigns privilege** — trace every write to a role, permission, or admin flag. Can
   any of them originate from client input? Coordinate with Tampering, which raises the write
   itself; this skill raises the privilege the write confers.
2. **Where the decision is read** — is authorization taken from a token claim, a header, or a
   cookie, or is it re-resolved from the authoritative store on each request?
3. **Coverage** — is the default deny or allow? List every route reachable without passing
   through the authorization middleware.
4. **Vertical paths** — enumerate administrative functionality and, for each, name the check
   that guards it or record that there is none.
5. **Horizontal paths** — for every operation taking a record identifier, is ownership
   verified, or only authentication?
6. **Recovery flows** — can password reset, MFA reset, or support impersonation be aimed at
   an account the attacker does not own?
7. **Revocation** — after logout, demotion, or password change, do existing tokens and
   sessions stop working? What is the token lifetime?
8. **Secondary login paths** — OAuth, SSO, API keys, and legacy endpoints each carry their own
   authorization decision. Check each rather than assuming the primary path covers them.
9. **Seeded accounts** — does the codebase create default administrative users with known
   credentials?

## Output Contract

Emit a single JSON object and nothing else — no preamble, no markdown fence, no commentary.

```json
{
  "use_case_id": "<from the supplied DFD>",
  "stride_letter": "E",
  "threats": [
    {
      "id": "T-<use_case_id>-E-001",
      "stride": "E",
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
      "cwe": ["CWE-269"],
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
not. Describe the escalation path and the missing check — do not write exploit code. If a
process has no credible Elevation of Privilege threat, omit it rather than padding.

## References

- CWE-269: Improper Privilege Management
- CWE-266: Incorrect Privilege Assignment
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-613: Insufficient Session Expiration
- CWE-1390: Weak Authentication
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
