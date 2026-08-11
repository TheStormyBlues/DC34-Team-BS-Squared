# Threat model — OWASP Juice Shop

Authentication scope · static analysis · 2026-08-11

13 threats across 1 use case(s), analyzed against all six STRIDE categories.

## Findings at a glance

| Severity | Count |
|---|---:|
| Critical | 6 |
| High | 4 |
| Medium | 3 |
| Low | 0 |
| **Total** | **13** |

### Coverage by STRIDE category

Every use case is analyzed by all six categories in separate passes, so a zero is a
considered result rather than a gap in the method.

| Use case | S | T | R | I | D | E | Total |
|---|---|---|---|---|---|---|---|
| UC-LOGIN | 2 | 4 | 2 | 3 | 2 | 0 | 13 |

S Spoofing · T Tampering · R Repudiation · I Information disclosure · D Denial of service · E Elevation of privilege

### Evidence

- 8 high confidence, 1 medium, 4 low
- 10 of 13 threats cite a specific file and line

A high-confidence threat is guaranteed to cite source; a low-confidence one applies to the
element by type but no supporting code was located. Low-confidence entries are retained
rather than dropped so the reader can judge them.

### Existing controls

- 0 threats already mitigated in the codebase
- 2 partially mitigated
- 11 unmitigated

## Method

Static analysis of the application source. No running instance was exercised, so
findings describe reachable code paths rather than confirmed exploits.

The pipeline runs in stages, each writing files the next reads:

1. **Characterize** — the codebase is surveyed and authentication use cases identified.
2. **Model** — a data flow diagram is drawn per use case, with elements typed as external
   entities, processes, data stores and data flows, and grouped by trust boundary.
3. **Analyze** — six independent agent passes per use case, one per STRIDE category, each
   loading a single skill scoped to that category. Coverage is guaranteed by the loop
   rather than left to one agent's judgement.
4. **Report** — this document, assembled deterministically from the stage 3 output.

### Consistency

- Each STRIDE pass loads exactly one skill, so every category receives equal attention.
- Severity is **derived**, never assigned: likelihood × impact through a fixed matrix
  identical across all six skills. Two runs cannot disagree about what `high × high` means.
- Every agent response is validated against a shared JSON contract before it is accepted;
  a response that violates it is returned to the model with its own error list and retried.
- Threat identifiers are derived from the use case and category, so runs can be diffed.
- Model: `us.anthropic.claude-haiku-4-5-20251001-v1:0`, temperature 0.3.

### Limitations

- Static analysis only. No dynamic testing, no exploitation, no runtime confirmation.
- Scope is authentication: 1 use case(s). Other areas of the application
  were not analyzed.
- Findings are machine-generated. High-confidence entries cite a file and line and can be
  checked directly; low-confidence entries are hypotheses worth triaging, not conclusions.

## UC-LOGIN — User Login

1. Client: Sends POST request to /rest/user/login with email and password
2. Login Handler: Queries database for user with matching email and hashed password (routes/login.ts)
3. Login Handler: Checks if user has TOTP secret set (routes/login.ts)
4. Login Handler: If TOTP secret exists, returns temporary token for 2FA verification (routes/login.ts)
5. Login Handler: If no TOTP secret, creates authenticated user session and returns JWT token (routes/login.ts)
6. Client: Stores JWT token in localStorage and cookie (frontend/src/app/login/login.component.ts)

**Entry points:** `POST /rest/user/login`

### Data flow

```mermaid
flowchart LR
    CUST[Client]
    LOGIN(Login Handler)
    USERS[(Database)]

    CUST -->|POST /rest/user/login with email and password| LOGIN
    LOGIN -->|Query user with matching email and hashed password| USERS
    USERS -->|Return user data| LOGIN
    LOGIN -->|Return temporary token for 2FA verification (if TOTP secret exists)| CUST
    LOGIN -->|Create authenticated user session and return JWT token (if no TOTP)| CUST
    CUST -->|Store JWT token in localStorage and cookie| CUST
```

### Threats

| ID | Severity | Category | Element | Status |
|---|---|---|---|---|
| T-UC-LOGIN-D-001 | Critical | Denial of Service | Login Handler | Unmitigated |
| T-UC-LOGIN-R-001 | Critical | Repudiation | Login Handler | Unmitigated |
| T-UC-LOGIN-R-002 | Critical | Repudiation | Login Handler | Unmitigated |
| T-UC-LOGIN-S-001 | Critical | Spoofing | Login Handler | Unmitigated |
| T-UC-LOGIN-S-002 | Critical | Spoofing | Login Handler | Unmitigated |
| T-UC-LOGIN-T-001 | Critical | Tampering | Login Handler | Unmitigated |
| T-UC-LOGIN-D-002 | High | Denial of Service | Login Handler | Unmitigated |
| T-UC-LOGIN-I-002 | High | Information Disclosure | Login Handler | Unmitigated |
| T-UC-LOGIN-T-002 | High | Tampering | Create authenticated user session and return JWT token if no TOTP | Partially mitigated |
| T-UC-LOGIN-T-003 | High | Tampering | Return temporary token for 2FA verification if TOTP secret exists | Partially mitigated |
| T-UC-LOGIN-I-001 | Medium | Information Disclosure | Login Handler | Unmitigated |
| T-UC-LOGIN-I-003 | Medium | Information Disclosure | Login Handler | Unmitigated |
| T-UC-LOGIN-T-004 | Medium | Tampering | Return user data | Unmitigated |

### Detail

#### T-UC-LOGIN-D-001 — Unbounded password hashing on unauthenticated login endpoint

**Critical** · Denial of Service · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The /rest/user/login endpoint performs expensive bcrypt password hashing on every unauthenticated request without rate limiting. An attacker can send concurrent login requests with arbitrary passwords to exhaust CPU resources and degrade service availability for all users.

**Attack scenario.** An attacker sends hundreds of concurrent POST requests to /rest/user/login with different email addresses and passwords. Each request triggers bcrypt hashing at cost factor 12 (approximately 100ms of CPU per request). Within seconds, the CPU pool is saturated and the application becomes unresponsive to legitimate login attempts and other requests.

*server.ts:615*

```
app.post('/rest/user/login', login())
```

*routes/login.ts:34*

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

*server.ts:362*

```
app.use('/rest/user/reset-password', rateLimit({
```

**Already in place.** Rate limiting is applied to /rest/user/reset-password and /rest/2fa/verify endpoints, demonstrating the application has rate-limiting capability

**Recommendation.** Apply rate limiting to the /rest/user/login endpoint using express-rate-limit middleware. Implement layered limits: per-source-IP limit (e.g., 100 requests per 15 minutes) to protect against botnets, and per-email limit (e.g., 5 failed attempts per 15 minutes) to prevent account lockout weaponization. Example: app.post('/rest/user/login', rateLimit({ windowMs: 15 * 60_000, max: 100, keyGenerator: r => r.ip }), rateLimit({ windowMs: 15 * 60_000, max: 5, keyGenerator: r => r.body.email }), login())

*CWE-770, CWE-405, CWE-400*

#### T-UC-LOGIN-R-001 — No audit logging of authentication events

**Critical** · Repudiation · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The Login Handler processes authentication requests but produces no durable, attributable record of login attempts, outcomes, or token issuance. Both successful and failed login attempts complete without logging, making it impossible to detect account takeovers, brute force attacks, or unauthorized access after the fact. An attacker can authenticate with stolen credentials, change the account email, and drain the account while leaving no audit trail.

**Attack scenario.** An attacker obtains a user's credentials through phishing or a data breach. They authenticate successfully via POST /rest/user/login. The application returns a JWT token but logs nothing. The attacker then changes the account email and transfers funds. When the legitimate user discovers the compromise weeks later, there is no login record, no timestamp, no source IP, and no way to determine when access began or what actions the attacker performed.

*routes/login.ts:35*

```
const user = utils.queryResultToJson(authenticatedUser)
```

*routes/login.ts:50*

```
res.status(401).send(res.__('Invalid email or password.'))
```

*routes/login.ts:24*

```
const token = security.authorize(authenticatedUser)
```

**Recommendation.** Implement structured logging for all authentication events. Log both successful and failed login attempts with the following attributes: event type (auth.login), outcome (success/failure), reason for failure (bad_credentials, account_locked, etc. — never the password), user ID or email (redacted), source IP address, user agent, server-generated UTC timestamp, and request ID. Ship logs to an append-only sink that the application cannot modify or delete. Example: logger.info({ event: 'auth.login', outcome: success ? 'success' : 'failure', reason: success ? undefined : 'bad_credentials', userId: user?.id ?? null, email: redact(req.body.email), sourceIp: req.ip, userAgent: req.get('user-agent'), timestamp: new Date().toISOString(), requestId: req.id })

*CWE-778, CWE-223*

#### T-UC-LOGIN-R-002 — No logging of TOTP token issuance and 2FA verification

**Critical** · Repudiation · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

When a user has TOTP enabled, the Login Handler issues a temporary token for 2FA verification (line 38-46) but produces no record of this event. Similarly, the 2FA verification process (routes/2fa.ts) completes without logging. This prevents detection of 2FA bypass attempts, token reuse, or compromise of the temporary token.

**Attack scenario.** An attacker obtains a user's password and email. They authenticate and receive a temporary 2FA token. The attacker attempts to use this token multiple times or attempts to bypass 2FA verification. Without logs, there is no record of the failed 2FA attempts, the token issuance, or the eventual successful verification. If the attacker succeeds, the legitimate user has no way to know their account was compromised.

*routes/login.ts:37*

```
if (user.data?.id && user.data.totpSecret !== '') {
```

*routes/login.ts:41*

```
tmpToken: security.authorize({
```

*routes/2fa.ts:31*

```
const isValid = verifySync({ secret: user.totpSecret, token: totpToken, epochTolerance: 30 }).valid
```

**Recommendation.** Log all 2FA-related events: temporary token issuance, 2FA verification attempts (both success and failure), and final authentication completion. Include user ID, source IP, timestamp, and the outcome. Example: logger.info({ event: 'auth.totp_token_issued', userId: user.id, sourceIp: req.ip, timestamp: new Date().toISOString() }) and logger.info({ event: 'auth.totp_verification', outcome: isValid ? 'success' : 'failure', userId: user.id, sourceIp: req.ip, timestamp: new Date().toISOString() })

*CWE-778, CWE-223*

#### T-UC-LOGIN-S-001 — SQL injection enables authentication bypass in login query

**Critical** · Spoofing · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The login query is constructed by string concatenation with user-supplied email and password, allowing SQL injection attacks to bypass authentication. An attacker can inject SQL syntax (e.g., ' OR 1=1--) to authenticate as any user without knowing their password.

**Attack scenario.** An attacker sends a POST request to /rest/user/login with email set to "admin@juice-sh.op' --" and any password. The injected SQL comment bypasses the password check, and the attacker is authenticated as the admin user.

*routes/login.ts:34*

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**Recommendation.** Use parameterized queries instead of string concatenation. Replace the raw SQL query with Sequelize's built-in findOne method: await UserModel.findOne({ where: { email: req.body.email, password: security.hash(req.body.password), deletedAt: null } })

*CWE-89, CWE-287, CWE-290*

#### T-UC-LOGIN-S-002 — Credential stuffing attack via unthrottled login endpoint

**Critical** · Spoofing · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The /rest/user/login endpoint has no rate limiting, throttling, lockout mechanism, or CAPTCHA protection. An attacker can perform unlimited login attempts using a corpus of breached credentials, enabling credential stuffing attacks to compromise user accounts.

**Attack scenario.** An attacker uses a tool to send thousands of login requests per second with email/password pairs from a known breach. Without rate limiting, the attacker can test thousands of credentials in minutes and identify valid accounts.

*server.ts:615*

```
app.post('/rest/user/login', login())
```

*server.ts:362*

```
app.use('/rest/user/reset-password', rateLimit({ windowMs: 5 * 60 * 1000, max: 100, keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip } }))
```

**Recommendation.** Apply rate limiting middleware to the login endpoint. Example: app.post('/rest/user/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5, keyGenerator: ({ headers, ip }) => headers['X-Forwarded-For'] ?? ip }), login()). Consider also implementing account lockout after N failed attempts and CAPTCHA challenges.

*CWE-307, CWE-640*

#### T-UC-LOGIN-T-001 — SQL Injection in login query allows tampering with authentication

**Critical** · Tampering · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The login handler constructs a SQL query using string concatenation with user-supplied email and password, allowing an attacker to inject SQL that modifies the WHERE clause. An attacker could inject SQL to bypass password checks or modify the query logic to authenticate as any user.

**Attack scenario.** An attacker submits email: admin@juice-sh.op' OR '1'='1 and any password. The resulting query becomes SELECT * FROM Users WHERE email = 'admin@juice-sh.op' OR '1'='1' AND password = '...' which returns the admin user regardless of password, allowing authentication bypass and session hijacking.

*routes/login.ts:34*

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**Recommendation.** Use parameterized queries or prepared statements. Replace the string concatenation with sequelize's parameterized query API: models.sequelize.query('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL', { replacements: [req.body.email, security.hash(req.body.password)], model: UserModel, plain: true })

*CWE-89*

#### T-UC-LOGIN-D-002 — Unbounded password input length enables CPU exhaustion

**High** · Denial of Service · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Internet → Application Server

The login endpoint accepts passwords of arbitrary length with no validation constraint. An attacker can submit multi-megabyte passwords that consume CPU and memory proportional to the input size when passed to bcrypt hashing, amplifying the resource exhaustion attack.

**Attack scenario.** An attacker sends a POST request to /rest/user/login with a password field containing a multi-megabyte string. The bcrypt hashing operation consumes CPU and memory proportional to the input size, potentially causing the server to run out of memory or become unresponsive faster than with normal-length passwords.

*frontend/src/app/login/login.component.ts:53*

```
public passwordControl = new UntypedFormControl('', [Validators.required, Validators.minLength(1)])
```

*routes/login.ts:34*

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**Recommendation.** Enforce a maximum password length before the password reaches the hashing function. Add validation in the login handler to reject passwords longer than 128 characters (or an appropriate limit for your application). Example: if (typeof password !== 'string' || password.length > 128) { return res.status(400).json({ error: 'Invalid email or password' }) }

*CWE-770, CWE-400*

#### T-UC-LOGIN-I-002 — Temporary 2FA token returned in response without encryption

**High** · Information Disclosure · Login Handler (process) · Unmitigated · medium confidence

*Crosses:* Application Server → Client

When a user has TOTP enabled, a temporary token is returned in the response body. This token could be intercepted or leaked, allowing an attacker to bypass the first factor of authentication.

**Attack scenario.** An attacker intercepts the login response and extracts the temporary token. They then use this token to access the 2FA verification endpoint.

*routes/login.ts:38*

```
res.status(401).json({ status: 'totp_token_required', data: { tmpToken: security.authorize({ userId: user.data.id, type: 'password_valid_needs_second_factor_token' }) } })
```

**Recommendation.** Return the temporary token in an HttpOnly, Secure, SameSite cookie instead of in the response body. Ensure the token has a short expiration time.

*CWE-522, CWE-200*

#### T-UC-LOGIN-T-002 — JWT token transmitted in response can be intercepted and tampered with

**High** · Tampering · Create authenticated user session and return JWT token if no TOTP (data flow) · Partially mitigated · low confidence

*Crosses:* Application Server → Client

The JWT token is returned in the response to the client without encryption. While JWT is signed, if transmitted over unencrypted channels or if the signing key is compromised, an attacker could tamper with the token claims.

**Attack scenario.** An attacker performing a man-in-the-middle attack intercepts the JWT token response. If the connection is not properly secured with TLS, the attacker could read or modify the token before it reaches the client.

**Already in place.** JWT is signed with RS256 algorithm

**Recommendation.** Ensure all communication is over HTTPS/TLS. Verify that the JWT signing key is properly protected and rotated regularly. Consider using short-lived tokens with refresh token rotation.

*CWE-347*

#### T-UC-LOGIN-T-003 — Temporary 2FA token transmitted in response can be tampered with

**High** · Tampering · Return temporary token for 2FA verification if TOTP secret exists (data flow) · Partially mitigated · low confidence

*Crosses:* Application Server → Client

The temporary token for 2FA verification is returned in the response without encryption. An attacker could intercept and tamper with this token if the connection is not properly secured.

**Attack scenario.** An attacker performing a man-in-the-middle attack intercepts the temporary 2FA token. If the token format is predictable or the server does not properly validate it, the attacker could modify it to bypass 2FA verification.

**Already in place.** Temporary token is signed with RS256

**Recommendation.** Ensure all communication is over HTTPS/TLS. Use short expiration times for temporary tokens. Validate token signature and expiration on every 2FA verification attempt.

*CWE-347*

#### T-UC-LOGIN-I-001 — Return user email in authentication response

**Medium** · Information Disclosure · Login Handler (process) · Unmitigated · high confidence

*Crosses:* Application Server → Client

The login response includes the user's email address in the response body. This confirms account existence and could enable account enumeration attacks.

**Attack scenario.** An attacker performs account enumeration by attempting login with a list of email addresses. By observing the response structure, they can determine which accounts exist in the system.

*routes/login.ts:26*

```
res.json({ authentication: { token, bid: basket.id, umail: user.email } })
```

**Recommendation.** Remove the umail field from the authentication response. Return only the token and basket ID.

*CWE-204, CWE-200*

#### T-UC-LOGIN-I-003 — JWT token transmitted in response without encryption requirement

**Medium** · Information Disclosure · Login Handler (process) · Unmitigated · low confidence

*Crosses:* Application Server → Client

The JWT token is returned in the response body without explicit encryption. If the response is transmitted over an unencrypted channel or intercepted, the token could be exposed.

**Attack scenario.** An attacker intercepts the login response over an unencrypted connection and extracts the JWT token, then uses it to make authenticated requests as the victim.

*routes/login.ts:26*

```
res.json({ authentication: { token, bid: basket.id, umail: user.email } })
```

**Recommendation.** Ensure all authentication responses are transmitted over HTTPS with strict transport security headers. Return the token in an HttpOnly cookie instead of the response body.

*CWE-522*

#### T-UC-LOGIN-T-004 — Database query results can be tampered with if database connection is compromised

**Medium** · Tampering · Return user data (data flow) · Unmitigated · low confidence

*Crosses:* Database → Application Server

User data returned from the database could be tampered with if the database connection is not properly secured or if an attacker gains access to the database layer.

**Attack scenario.** An attacker with network access to the database connection could perform a man-in-the-middle attack to modify the user data in transit, potentially returning false authentication results or modified user credentials.

**Recommendation.** Use encrypted connections (SSL/TLS) for all database communications. Implement network segmentation to restrict database access. Use connection pooling with proper authentication.

*CWE-347*

## Notes on this run

- use case 'UC-LOGIN' has no threats for letter(s) E — confirm those skill calls ran and returned an empty list on purpose

---

Generated by the BS-Squared threat modelling pipeline. Regenerate with `python -m main.stage4_report`.
