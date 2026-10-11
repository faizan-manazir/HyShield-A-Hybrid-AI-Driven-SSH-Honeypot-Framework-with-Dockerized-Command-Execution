# SIEM API Security Notes

## Safe local default

The Express API binds to `127.0.0.1:5000` by default. This keeps it reachable only from the same host unless the deployment explicitly changes the bind address.

The browser CORS allow-list defaults to `http://localhost:3000`. Configure additional trusted browser origins with `CORS_ORIGINS`, as a comma-separated list of complete origins, for example:

```dotenv
CORS_ORIGINS=http://localhost:3000,https://siem.example.com
```

For an intentional container or remote deployment, set `HOST=0.0.0.0` only when the surrounding network exposure is understood.

## Request and browser hardening

The API sets defensive response headers (content-type sniffing disabled, framing denied, referrer suppressed, no-store caching, and unused browser capabilities disabled). The Express JSON parser accepts strict JSON and limits request bodies to 1 MB. Oversized bodies receive HTTP 413; malformed JSON receives HTTP 400. CORS rejection returns HTTP 403. These controls reduce exposure but do not authenticate callers.

## Important limitation: authentication

The current API does **not** implement application-level authentication or authorization. CORS is a browser policy, not an access-control mechanism; clients outside a browser can call the API directly. Do not expose this service to an untrusted network or the public internet as-is.

Before remote exposure, place it behind an authenticated reverse proxy or VPN and restrict network access. Native user authentication and authorization remains a separate required security task. WebSocket origin validation is also not authentication. WebSocket connections must send a JSON first message with type set to auth and token set to a valid bearer token within five seconds; the server closes connections that fail authentication before sending its connection acknowledgement.

## Frontend API URL

The dashboard uses `NEXT_PUBLIC_API_BASE_URL` for its API base URL. If unset, it falls back to `http://localhost:5000`. Set it at frontend build time for a different deployment origin.

## Dependency advisories

Review `../docs/FRONTEND_DEPENDENCY_AUDIT_REVIEW.md` before changing frontend tooling dependencies. Do not use `npm audit fix --force` or downgrade Next.js to silence advisories without compatibility testing. The audit workflow reports findings; a successful workflow job does not mean all advisories are remediated.


## Phase 2: native API authentication (in progress)

The backend authentication implementation is being introduced on a separate branch and is not approved for deployment until the dashboard login flow and end-to-end tests are complete.

Required server-side environment:
- `SIEM_ADMIN_USERNAME`: a dedicated administrator username.
- `SIEM_ADMIN_PASSWORD_HASH`: scrypt password hash in `scrypt$<salt-hex>$<hash-hex>` format. Never store the plaintext password in source control.
- `SIEM_AUTH_SECRET`: a randomly generated secret of at least 32 bytes. Keep it in the deployment secret store; do not reuse it across environments.

The login endpoint issues a short-lived bearer token. The browser stores the token in sessionStorage, which is accessible to JavaScript; mitigate XSS and use HTTPS for any remote access. The frontend tracks the token expiry and provides explicit sign-out, but server-side revocation is not implemented. Protected API routes reject missing/invalid tokens. Mutating HTTP methods require the administrator role. This initial implementation is a single-admin bootstrap, not a complete multi-user/RBAC system; the initial login endpoint now applies an in-memory per-client failure limit and logs login outcomes without logging credentials. This limit resets on process restart and is not a substitute for edge-level rate limiting. Account lifecycle, token revocation, and durable audit logging still need review before production.

## Remote deployment boundary

Do not bind the service to a public interface or open inbound firewall ports during implementation. For remote access, prefer a VPN/private network. If an internet-facing deployment is eventually approved, use a maintained reverse proxy with TLS, strong authentication, request limits, restricted source networks, and explicit WebSocket proxy/origin configuration. Keep the Node API on loopback or a private container network behind that proxy. CORS alone is not access control.

Never commit real credentials or secrets. Rotate any secret that was accidentally exposed.
