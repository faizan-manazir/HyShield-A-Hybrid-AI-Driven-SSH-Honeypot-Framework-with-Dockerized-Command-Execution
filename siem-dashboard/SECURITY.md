# SIEM API Security Notes

## Current authentication status

The SIEM API has an application-level authentication foundation in the merged implementation. This document replaces earlier notes that described native API authentication as still in progress.

The implementation uses:
- scrypt-based password verification;
- HMAC-SHA256-signed bearer tokens with a 15-minute lifetime;
- a public `POST /api/auth/login` endpoint;
- authentication on other `/api` routes, except the public health endpoint;
- administrator-only mutation requests and read-only analyst access;
- an in-memory failed-login throttle;
- a WebSocket authentication message required as the first message within five seconds.

See [SIEM Security A–Z Documentation](../docs/SIEM_SECURITY_A_TO_Z.md) for the consolidated implementation record, testing checklist, known limitations, and deployment guidance.

## Required environment variables

- `SIEM_ADMIN_USERNAME`: dedicated administrator username.
- `SIEM_ADMIN_PASSWORD_HASH`: scrypt password hash in `scrypt$<salt-hex>$<hash-hex>` format. Never commit the plaintext password or hash.
- `SIEM_AUTH_SECRET`: randomly generated secret of at least 32 bytes. Keep it in protected environment configuration or a secret manager; do not reuse it across environments.

Generate a fresh random secret with Node.js:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

The authentication setup is a single-admin bootstrap, not a complete multi-user identity lifecycle. The token lifetime is 15 minutes. Server-side token revocation was not implemented in the recorded version.

## Safe local default

The Express API binds to `127.0.0.1:5000` by default. This keeps it reachable only from the same host unless the deployment explicitly changes the bind address.

The browser CORS allow-list defaults to `http://localhost:3000`. Configure trusted browser origins with `CORS_ORIGINS`, as a comma-separated list of complete origins, for example:

```dotenv
CORS_ORIGINS=http://localhost:3000,https://siem.example.com
```

The dashboard uses `NEXT_PUBLIC_API_BASE_URL` for its API base URL. If unset, it falls back to `http://localhost:5000`. Set it at frontend build time for a different deployment origin.

Keep the API bound to loopback during local development. Do not set `HOST=0.0.0.0` or open inbound firewall ports as a shortcut for testing.

## Request and browser hardening

The API uses strict JSON parsing and limits JSON request bodies to 1 MB. Malformed JSON receives HTTP 400; oversized bodies receive HTTP 413; rejected CORS origins receive HTTP 403. The server disables Express `X-Powered-By` and sets defensive headers including content-type sniffing disabled, framing denied, referrer suppressed, no-store caching, and unused browser capabilities disabled.

These controls reduce exposure but do not replace authentication or network access controls. CORS is a browser policy and does not prevent direct API access by non-browser clients. A full Content Security Policy (CSP) review was not recorded as complete.

## Login throttling and logging

The login endpoint limits failed attempts to 10 per client within 15 minutes, responds with HTTP 429 and `Retry-After` when throttled, and keeps a capped in-memory client map with pruning/eviction. Login outcomes are logged without logging credentials.

The throttle resets on process restart and is not a substitute for edge-level rate limiting. Review trusted proxy/client identity behavior before deployment behind a reverse proxy. Durable, tamper-resistant audit-log retention was not established as complete.

## Frontend session considerations

The frontend stores the bearer token and expiry in `sessionStorage`. This storage is accessible to JavaScript running on the same origin; an XSS vulnerability could expose the token. The frontend tracks expiry, supports logout, attaches the token to protected API requests, and clears the session/redirects when the API returns HTTP 401.

A route-transition/fetch-wrapper fix was included in commit `dc2aa62563f31f5273afe8c3946929d2ecc26fe9`. CI passed for that commit, but browser-level end-to-end testing is still required to verify login, navigation, refresh, logout, and expiry behavior in the target environment.

## WebSocket authentication

A WebSocket client must send a JSON authentication message as its first message within five seconds:

```json
{
  "type": "auth",
  "token": "<access-token>"
}
```

The token must be valid. Connections that fail authentication are closed with code `1008`. A successful authentication acknowledgement does not prove that live event broadcasting is complete; verify event delivery separately. Review WebSocket proxy/origin configuration before any remote deployment.

## Dependency advisories

Review `../docs/FRONTEND_DEPENDENCY_AUDIT_REVIEW.md` before changing frontend tooling dependencies. Do not use `npm audit fix --force` or downgrade Next.js to silence advisories without compatibility testing. An audit workflow passing does not mean every advisory has been remediated.

## Remote deployment boundary

No public deployment or public exposure was approved or performed as part of the recorded work.

Before remote access, prefer a VPN/private network. If an internet-facing deployment is explicitly approved, use a maintained reverse proxy with TLS, strong authentication, request limits, edge rate limiting, restricted source networks, and explicit WebSocket proxy/origin configuration. Keep the Node API on loopback or a private container network behind that proxy. Review secrets management, monitoring, durable audit retention, recovery, and incident response before deployment.

## Known limitations / required follow-up

- The bootstrap is not a complete multi-user identity lifecycle.
- Server-side token revocation is not implemented in the recorded version.
- Login throttling is in memory and resets after restart.
- Tokens in `sessionStorage` are accessible to same-origin JavaScript.
- Durable/tamper-resistant audit-log retention is not confirmed.
- A full CSP review is outstanding.
- Browser end-to-end tests remain necessary.
- Live event broadcasting must be validated separately from WebSocket authentication.
- Production TLS/proxy/network configuration has not been validated.
- Use a unique strong password and fresh random signing secret before any remote access.

Never commit credentials, password hashes, tokens, or signing secrets. Rotate any secret that may have been exposed.
