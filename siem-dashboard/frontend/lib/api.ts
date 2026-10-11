/** Base URL for the SIEM API. Configure NEXT_PUBLIC_API_BASE_URL for remote deployments. */
export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:5000'
).replace(/\/$/, '');
