# SIEM API Security Notes

## Safe local default

The Express API binds to `127.0.0.1:5000` by default. This keeps it reachable only from the same host unless the deployment explicitly changes the bind address.

The browser CORS allow-list defaults to `http://localhost:3000`. Configure additional trusted browser origins with `CORS_ORIGINS`, as a comma-separated list of complete origins, for example:

```dotenv
CORS_ORIGINS=http://localhost:3000,https://siem.example.com
```

For an intentional container or remote deployment, set `HOST=0.0.0.0` only when the surrounding network exposure is understood.

## Important limitation: authentication

The current API does **not** implement application-level authentication or authorization. CORS is a browser policy, not an access-control mechanism; clients outside a browser can call the API directly. Do not expose this service to an untrusted network or the public internet as-is.

Before remote exposure, place it behind an authenticated reverse proxy or VPN and restrict network access. Implementing native user authentication and role-based authorization remains a separate required security task.

## Frontend API URL

The dashboard uses `NEXT_PUBLIC_API_BASE_URL` for its API base URL. If unset, it falls back to `http://localhost:5000`. Set it at frontend build time for a different deployment origin.
