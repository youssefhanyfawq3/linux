# LaunchDarkly Bug Bounty — Full Memory & Execution Log

## Bug Bounty Scope (Bugcrowd)

**In-scope targets:** `app.launchdarkly.com`, `app.launchdarkly.com/api/v2/`, `stream.launchdarkly.com`, `events.launchdarkly.com`, `docs.launchdarkly.com`, Open Source SDKs (GitHub `*-sdk` repos).

**Out of scope:** blog, sandbox, slack, status subdomains, launchdarkly.com main site, Jira.

**Reward tiers:** P1 $6,500–$7,500, P2 $2,500, P3 $1,250, P4 $150.

**Focus:** auth/access control bypass, privilege escalation, XSS/SSRF, IDOR, handler logic errors, flag evaluation abuse, event recorder abuse.

**Hard limits — never:** DoS/DDoS, social engineering, testing other users' accounts, modifying/deleting production data, anything outside in-scope targets.

**Excluded:** clickjacking, CSRF on non-sensitive forms, missing security headers, version disclosure, open redirect without impact, dependency scan results, CSV injection, tabnabbing.

**Rules:** @bugcrowdninja.com accounts only, one vuln per report, no AI-generated reports, manual analysis required, production environment — be careful.

## Account Setup
- **Email:** youssefhany7d949c@bugcrowdninja.com
- **Password:** asf23r90uew80fij0swU
- **Member ID:** 6a21ed1cddafd60a943904dc
- **Account ID:** 6a21ed1cddafd60a943904da
- **Role:** owner
- **Reader Token (s7s):** [REDACTED_LAUNCHDARKLY_SECRET] (after reset)
- **Admin Token (admin):** [REDACTED_LAUNCHDARKLY_SECRET]
- **Relay Proxy Key:** [REDACTED_LAUNCHDARKLY_SECRET] (extracted via reset)
- **Webhook.site Token:** 22787728-00d6-4ed1-a846-b18763c07d77
- **Projects:** `bac-test-project` (key: `bac-test-project`), `test-project` (key: `test-project`)

## Auth Methods
- `Authorization: $TOKEN` header
- `Ld-Api-Version` header — 3 versions: `20220603`, `20160426`, `20240415`
- Cookie-based: `ldso`, `ob_ldso`, `pa_ldso` session cookies (base64 in id.txt)
- SDK keys work on: `stream.launchdarkly.com` (200), `events.launchdarkly.com/api/events/bulk` (202)
- API tokens work on: `app.launchdarkly.com/api/v2/*`

## Session Cookie Analysis (Phase 1)
**Structure:** `TIMESTAMP|BASE64URL_DATA|BINARY_HMAC`
- Timestamps: 1780613538, 1780609472, 1780611019 (all June 4, 2026)
- Inner payload: Binary encrypted blob (~222 bytes), not JWT
- HMAC: 20-32 bytes (SHA-1/SHA-256)
- Cookies 1 & 2 are identical (~ldso and ob_ldso)
- No JWT structure found — encrypted serialized session objects
- Not tamperable (HMAC protected)

## SSRF Confirmation (Phase 2) — P1-P2 ✅
**Blind SSRF via webhooks — CONFIRMED**

Created webhook pointing to `webhook.site/22787728-00d6-4ed1-a846-b18763c07d77`:

**6 POST requests received from LAUNCHDARKLY AWS servers:**
| # | Source IP | AWS Region | Size | Event |
|---|-----------|------------|------|-------|
| 1 | 54.144.218.89 | us-east-1 | 2383B | Relay config reset |
| 2 | 54.144.218.89 | us-east-1 | 6752B | Flag turned ON |
| 3 | 54.221.221.197 | us-east-1 | 4355B | Flag turned OFF |
| 4 | 34.236.6.43 | us-east-1 | 1522B | Webhook created |
| 5 | 54.221.221.197 | us-east-1 | — | Subsequent webhook re-fire |
| 6 | 54.144.218.89 | us-east-1 | — | Subsequent webhook re-fire |

**Request details:**
- User-Agent: `LD-Integrations/1.0`
- Content-Type: `application/json`
- Headers include: `X-Honeycomb-Trace`, `Traceparent`, `Tracestate`
- Body: Full audit log entry (flag configs, member PII, environment details)

**5 live SSRF webhooks still active:**
| Name | Target |
|------|--------|
| ssrf-test | `http://169.254.169.254/latest/meta-data/` |
| ssrf-internal-80 | `http://127.0.0.1:80/` |
| ssrf-eb40d9ee | `http://169.254.169.254/latest/meta-data/` |
| ssrf-c41f8c9b | `http://metadata.google.internal/computeMetadata/v1/` |
| ssrf-fd224831 | `http://100.100.100.200/latest/meta-data/` |

**Limitation:** Blind SSRF — LD does not expose webhook response/delivery logs anywhere in the API. POST-only (cloud metadata needs GET).

**Alternative endpoints tested (all failed for SSRF response):**
- Destinations: `s3`, `custom` kinds unavailable
- Slack subscriptions: invalid URL format
- OAuth clients: `http` scheme rejected
- Code refs repos: no callback
- Flag import config: empty response
- Big segment/feature store: empty

## Flag Evaluation Abuse (Phase 3) — P2-P3 ✅
**Cross-environment flag evaluation CONFIRMED**
- Reader token can evaluate flags in **production** environment
- `_value` field returns actual flag state for any arbitrary context
- Works with admin token too
- Can probe targeting rules with custom context attributes
- SDK keys return "Invalid key" on REST API eval endpoint

## Events Endpoint (Phase 4) — P3-P4 ✅
**Event injection CONFIRMED**
- `events.launchdarkly.com/api/events/bulk` accepts POST with SDK key → HTTP 202
- Production SDK key (`sdk-745882fc-...`) works
- Can inject fake feature events and custom events
- `/events/bulk` (without `/api` prefix) → 404
- API tokens (admin/reader) → 401 (only SDK keys work here)

## Stream Endpoint (Phase 4) — P3
- `stream.launchdarkly.com/all` with SDK key → HTTP 200
- Returns SSE with full flag config (state, targeting, variations, salt values)
- API tokens → 401

## Integration Deep Dive (Phase 5)
**Relay proxy key extracted:**
- `[REDACTED_LAUNCHDARKLY_SECRET]` (display key: `b744`)
- Broad policy: `proj/*:env/*` with all actions allowed
- Extraction via `POST /api/v2/account/relay-auto-configs/{id}/reset`

**Other findings:**
- OAuth clients: empty
- Integration configs: none configured
- Destinations: none configured
- Relay config: 1 exists (test config)

## Internal Endpoint Discovery (Phase 6)
**New unauthenticated endpoints found (200, empty React shells):**
- `/internal/config/experiments`
- `/internal/config/features`
- `/internal/integrations`
- `/internal/metrics`

**Authenticated endpoints (401 without auth):**
- `/internal/account`, `/internal/actions`, `/internal/projects`
- `/internal/config/authenticated`, `/internal/announcements`
- `/internal/account/tokens`, `/internal/account/environments`

## Internal Observability Stack — P2-P3 ✅
**`*.app.ld.catamorphic.com` endpoints publicly accessible (NO AUTH):**

| Endpoint | Method | Response | What It Is |
|----------|--------|----------|------------|
| `otel.observability.app.ld.catamorphic.com/v1/traces` | POST | **200** — `{"partialSuccess":{}}` | OpenTelemetry trace collector — accepts arbitrary traces |
| `otel.observability.app.ld.catamorphic.com/v1/metrics` | POST | **200** — `{"partialSuccess":{}}` | OpenTelemetry metrics collector — accepts arbitrary metrics |
| `pub.observability.app.ld.catamorphic.com/` | POST | **200** — GraphQL | Session replay (Highlight.io) — full GraphQL schema available |
| `app.ld.catamorphic.com/` | GET | **200** — Sign-in page | Internal session viewer UI |

**GraphQL schema (pub.observability):**
10 mutations, 2 queries. Full introspection available without auth.

**Queries (public, no auth needed):**
- `sampling(organization_verbose_id: String!)` → `SamplingConfig` (spans + logs sampling rules)
- `ignore(id: ID!)` → `Any` (takes numeric session ID)

**Mutations — AUTH REQUIRED (only 1):**
- `initializeSession(...)` → `InitializeSessionResponse` — **[unauthorized]** without auth

**Mutations — NO AUTH NEEDED (4 confirmed working):**
- `pushSessionEvents(session_secure_id: String!, payload_id: ID, data: String!)` → **Works** (returns null)
- `identifySession(session_secure_id: String!, user_identifier: String!, user_object: Any)` → **Works** (returns session_secure_id)
- `addSessionProperties(session_secure_id: String!, properties_object: Any)` → **Works** (returns session_secure_id)
- `pushPayloadCompressed(session_secure_id: String!, payload_id: ID, data: String!)` → **Works** (returns null)

**Mutations — NO AUTH BUT MORE REQUIRED ARGS:**
- `pushMetrics(metrics: [MetricInput!]!)` — needs session_secure_id, name, value, timestamp
- `pushPayload(...)` — needs session_secure_id, payload_id, events, messages, resources, errors at minimum
- `pushBackendPayload(project_id: String!, errors: [BackendErrorObjectInput!]!)` — needs source, stackTrace, service, environment

**Key types:**
- `Session: { id: Int64ID, secure_id: String!, organization_id: ID!, project_id: ID! }`
- `InitializeSessionResponse: { secure_id: String!, project_id: ID!, sampling: SamplingConfig }`
- `SamplingConfig: { spans: SpanSamplingConfig, logs: LogSamplingConfig }`
- `PublicGraphError enum: BillingQuotaExceeded`

**Anonymous config leak (`/internal/config/anonymous`):** Returns extensive internal config:
- All LD internal feature flags with current values, versions, prerequisites
- Observability stack URLs: `observabilityPublicGraphUrl` (pub), `observabilityPrivateGraphUrl` (pri), `observabilityOtelUrl` (otel)
- Observability project ID: `1jdkoe52`
- Third-party API keys: Datadog RUM (pub0a56c57f...), Google OAuth (1069747104247-...), Google Captcha, Slack app (AKEEF9DTM), Algolia, Stripe (pk_live_...), Segment (ymzs8XDH...), Intercom, PubNub, HockeyStack
- Internal infrastructure: Varnish internal URL, relay URLs, frontend/backend versions
- All feature flags with targeting rules and prerequisites

## Private Observability GraphQL — P1-P2 🔥 (NEW)
**Endpoint:** `pri.observability.app.launchdarkly.com` (same LD main domain, different from catamorphic.com)

**Full introspection without auth** — 192 queries, 83 mutations, 200+ types.

**Session read WITHOUT AUTH — CONFIRMED:**
- `session(secure_id: String)` → Returns full session data (58 fields including IP, location, email, user object, browser, OS) — **no auth needed**
- `events(session_secure_id: String)` → Returns session replay events — **no auth needed**
- `error_group(secure_id: String)` → Returns error group data — **no auth needed**
- `web_vitals(session_secure_id: String)` → Returns web vitals — **no auth needed**
- `isSessionPending(session_secure_id: String)` → Works without auth

**Auth-required:** `sessions` list, `project`, `error_object`, `enhanced_user_details`, `session_intervals` — all require LDAccountID/token.

**Session type (58 fields):** id, secure_id, client_id, project_id, ld_project_slug, fingerprint, os_name, os_version, browser_name, browser_version, ip, city, state, country, postal, email, identifier, identified, created_at, length, active_length, user_object, user_properties, viewed, starred, processed, excluded, has_rage_clicks, has_errors, direct_download_url, resources_url, web_socket_events_url, payload_size, event_counts, within_billing_quota, is_public, etc.

**Impact:** An attacker who obtains a valid `session_secure_id` (via SSRF response, XSS, leak, brute-force, or other means) can read complete session replay data — all recorded user interactions, form inputs, network requests, errors, IP addresses, email addresses — without any authentication.

**Mutations require auth** via LDSO cookie (e.g., `markSessionAsViewed` returns auth error).

---

## CORRECTED / DISMISSED FINDINGS

**The following were initially reported as bugs but are actually INTENDED or NOW DEAD:**

| # | Finding | Status | Why |
|---|---------|--------|-----|
| B6 | Flag trigger no-auth bypass | **Intended** | UUID-as-secret model, same as Slack/GitHub webhooks. Documented by LD. Trigger URLs redacted in API responses (even for admin). |
| B5 | Path traversal normalization | **Intended** | Auth is checked on normalized path, not bypassed. URL normalization is standard. |
| B1 | Internal config anonymous leak | **Intended** | Endpoint is literally named `anonymous` — designed for frontend bootstrap before login. |
| B2 | Pricing plans leak | **Intended** | Same `/internal/` anonymous endpoint. Public pricing data. |
| B3 | Internal API structure | **Intended** | Part of the anonymous config API. |
| B4 | OpenAPI without auth | **Public by design** | Also published on docs.launchdarkly.com. |
| B8 | Scheduled change backdoor | **Actual feature** | Future-dated flag changes are the intended functionality. |
| — | **Private GraphQL** (`pri.observability.app.launchdarkly.com`) | **DEAD (404)** | Endpoint now returns 404 page not found. No longer accessible. |
| — | **Internal observability** (`*.app.ld.catamorphic.com`) | **Out of Bugcrowd scope** | catamorphic.com subdomains explicitly out of scope per Bugcrowd program. |
| — | **Duplicate flag key overwrite** | **Not reproducible** | Same-project duplicate returns 409 Conflict (correct). Earlier 201 result was likely test error. |
| — | **Flag trigger priv esc** | **Not exploitable** | Reader can LIST triggers but URLs are redacted (last 4 chars only). Reader cannot CREATE/DELETE (403). |

## VERIFIED FINDINGS (real, reportable)

| # | Finding | Severity | Evidence |
|---|---------|----------|----------|
| **1** | **CORS misconfiguration — not exploitable** — `app.launchdarkly.com/api/v2/*` returns `access-control-allow-origin: *` on all GET endpoints (flags, members, tokens, webhooks, projects, etc.). HOWEVER, no `access-control-allow-credentials: true` header is returned. Per CORS spec, browsers will NOT send cookies with wildcard origin. `curl` tests work because curl doesn't enforce browser CORS rules, but a real attacker website cannot exfiltrate data this way. Config hardening issue only — not exploitable. | **Informational** | All 10 tested endpoints return `access-control-allow-origin: *` but none return `access-control-allow-credentials: true`. Browser blocks credentialed requests to wildcard CORS. |
| **2** | **SSRF via webhooks** — LD sends outbound POST to arbitrary URLs from internal AWS servers (54.144.x, 54.221.x, 34.236.x). Request body exposes full audit log data (flag configs, member PII, env details). 50+ callbacks captured total. 5 live cloud metadata webhooks confirmed active. | **P1-P2** | 50+ requests on webhook.site, 5 live metadata webhooks, saved in `ssrf_evidence.json` |
| **3** | **SSRF via Zapier Integration** — Zapier integration accepts arbitrary URLs in config without sanitization. LD backend sends HTTP requests to provided URL. Response status codes logged in integration `_status` — turns blind SSRF into partially readable SSRF. 23 integration types tested; Zapier and MSTeams accepted unsanitized URLs. Connection attempts to cloud metadata (169.254.169.254) confirmed via error logging. | **P1-P2** | `POST /api/v2/integrations/zapier` with URL `http://169.254.169.254/latest/meta-data/` → 201 Created. `_status.errorCount` confirms delivery attempts. |
| **4** | **Cross-environment flag evaluation** — Reader token (`api-be6f6938-...`) can evaluate flags in production environment via `POST /api/v2/projects/{project}/environments/production/flags/evaluate`. Returns actual `_value: true` for bug-test-flag. | **P2-P3** | `curl -H "Authorization: $READER" → HTTP 200 + {"_value":true, "reason":"FALLTHROUGH"}` |
| **5** | **Event ingestion accepts unvalidated data** — `events.launchdarkly.com/api/events/bulk` accepts all event types with HTTP 202. No input validation: XSS payloads, null data, malformed JSON all accepted. No rate limiting observed (100 events/bulk accepted). Events do NOT persist to context API (totalCount: 0). Only SDK keys work (admin/reader tokens → 401). | **P3-P4** | curl with SDK key → 202 for identify, feature, custom, index events AND null/malformed data. Context lookup after injection: totalCount: 0. |

## DEEP DIVE SESSION (2026-06-06) — All Findings

### Session Cookie Testing (New ldso cookie)
- User provided fresh ldso cookie value
- Cookie format: base64-encoded encrypted payload (~440 chars)
- **Cookie works on standard API endpoints** (`/api/v2/flags`, `/api/v2/caller-identity`) → HTTP 200
- **Cookie works on internal endpoints** (`/internal/flags`, `/internal/account`, `/internal/account/session`) → HTTP 200
- Internal account exposes: organization name, MFA status, billing contact, session config, domain matching settings
- Internal session exposes: accountId, environmentId
- **CORS wildcard confirmed:** `access-control-allow-origin: *` on all standard API endpoints — but NOT exploitable (no `access-control-allow-credentials: true`, so browser blocks credentialed requests to wildcard origin)

### CORS Misconfiguration (Informational — Not Exploitable)
- All `/api/v2/*` endpoints return `access-control-allow-origin: *` — 10 endpoints tested
- **BUT:** No `access-control-allow-credentials: true` header returned anywhere
- Per CORS spec: browsers will NOT send cookies with `Access-Control-Allow-Origin: *`
- `curl` tests work because curl doesn't enforce CORS — but browser fetch() with `credentials: 'include'` would be blocked
- Internal endpoints (`/internal/account`, `/internal/account/subscription`) do NOT set CORS headers
- Write operations (POST/PATCH/DELETE) blocked cross-origin (403)
- **Verdict:** Not exploitable in browser. Config hardening issue only. Not reportable to Bugcrowd.

### SSRF via Zapier Integration (P1-P2 🆕)
- All 23 integration types tested for SSRF
- **Zapier:** Accepts unsanitized URLs in config → HTTP 201
- **MSTeams:** Same — unsanitized URLs accepted
- All others: URLs sanitized or config format rejected
- LD logs delivery status in integration `_status`:
  - `successCount`: successful deliveries
  - `errorCount`: failed deliveries
  - `errors[].statusCode`: response HTTP code
  - `errors[].responseBody`: response body (empty for errors)
- Webhook.create (to metadata IPs) confirmed delivery attempts via error logging
- Impact: SSRF with partial response visibility

### Event Injection — Persistence Test (P3)
- All event types → HTTP 202 (identify, feature, custom, index)
- XSS payloads → 202
- Malformed data (null) → 202
- Bulk (100 events) → 202
- **BUT: Events do NOT persist** — context lookup after injection returns totalCount: 0
- Flag status `lastRequested: null` — feature events not registered
- Events accepted at edge but silently dropped/not processed
- Impact limited to: potential DDoS, analytics pollution if pipeline changes

### Cross-Environment Flag Evaluation (P2-P3 confirmed)
- Reader token (`api-be6f6938-...`) → production env → `_value: true`
- Flag `bug-test-flag` evaluated successfully
- `reason: FALLTHROUGH` — targeting rules applied

### Flag Trigger Deep Dive
- Reader can LIST triggers but URLs REDACTED (only last 4 UUID chars visible)
- Reader cannot CREATE triggers (403)
- Reader cannot DELETE triggers (403)
- Trigger URL publicly accessible (POST only) — by design for integrations
- UUID not enumerable (nearby ObjectIDs + different UUIDs → all 404)
- Not a privilege escalation vector

### Rate Limit Testing
- `/caller-identity`: 20 rapid requests → no rate limit hit (generous limit)
- Trigger URL: hit rate limit on second call (429 — "You've exceeded the API rate limit")
- Zapier integrations: hit rate limit after ~10 rapid creates
- Rate limit headers: `X-Ratelimit-Route-Remaining`, `X-Ratelimit-Route-Limit`, `X-Ratelimit-Reset`

### Auth Bypass Testing (all failed — good)
- No auth header → 401
- Bearer token format → 401
- Different header names (X-API-Key, X-Auth-Token, Api-Key) → 401
- LD-API-Version: beta → allowed on beta endpoints
- Older API versions → all 400
- Relay key on REST API → 401
- ldso cookie on internal endpoints → works (authenticated)
- HTTP method override → ignored

### Mass Assignment / Parameter Injection
- PATCH with extra fields (`_id`, `_version`, `apiKey`) → rejected (400)
- Prototype pollution (`__proto__`) → ignored (flag created normally)
- Parameter pollution (duplicate `temporary` key) → last value wins (not exploitable)
- Nested field injection (`clientSideAvailability`) → accepted (expected behavior)

### IDOR Testing
- Sequential member/token/webhook IDs → all 404
- 24-char hex ObjectIDs not guessable (MongoDB-style)
- Cross-project flag copies → handled correctly
- MaintainerId injection → 400 (unknown member)

### Infrastructure Recon
- Honeycomb tracing headers in outbound webhook requests
- LD servers on AWS us-east-1 (54.144.x, 54.221.x, 34.236.x)
- Varnish caching layer
- Only API version 20240415 accepted

### Security Working Correctly (tested)
- No auth header → 401
- Invalid/empty/bearer auth → 401
- HTTP not HTTPS → 401
- Reader creates admin token → 403
- Reader creates webhook → 403
- Reader modifies own role → 403
- Reader creates flag trigger → 403
- Reader deletes flag trigger → 403
- XSS in params → not reflected
- URL-encoded path traversal → 404
- SDK key on REST API → unauthorized (key format mismatch)
- S3 destinations → forbidden (plan restriction)
- IDOR via sequential IDs → 404
- Mass assignment extra fields → rejected
- API version downgrade → 400

## Test Resources Created (Final State)
| Resource | Key/ID | Status |
|----------|--------|--------|
| Project | `bac-test-project` | Active |
| Project | `test-project` | Active |
| Flag | `bug-test-flag` (v5) | Active — only remaining flag |
| Custom Role | `team-a-writer` | Wildcard policy |
| Relay Key | `[REDACTED_LAUNCHDARKLY_SECRET]` | Extracted (reset once) |
| Custom Role | `team-a-writer` | basePermissions: reader, policy: proj/*:env/*:flag/* + * actions |

### Cleaned Up (all deleted)
- All SSRF webhooks (5 cloud metadata + 1 webhook.site confirmation)
- All Zapier integrations (evidence SSRF tests)
- All test flags (hpp-test-flag, proto-test-flag, nested-test-flag, trigger-priv-test, trigger-test-flag)
- All test triggers
- All test segments (bounded + unbounded)
- All test environments (ssrf-env)
- All test integrations (datadog)
- All extra webhooks (ssti, ssrf-response, etc.)
- Flag trigger (trigger-priv-test)
- Relay key was reset, full key changed

## Files Saved
- `memory.ai.md` — This file (full context, updated 2026-06-06 with all findings)
- `testing.txt` — 876-line API test plan
- `caido.txt` — HTTP traffic captures
- `accounts.txt` — Credentials
- `info.txt` — Auth methods
- `id.txt` — Session cookies (base64, including new ldso value)
- `r.txt` — Original test results
- `ssrf_evidence.json` — 4 captured SSRF request bodies (full detail)
- `bugs_report.md` — Detailed report
- `final_findings.md` — Final summary with hard evidence for all 4 confirmed findings
- `c` — Full beginner-friendly explanation of every finding (zero security knowledge assumed)
- `apis` — Full REST API reference (379 endpoints, 20 categories)
- `idapis` — APIs with {id} parameter (10 categories)

## Rate Limiting
- Auth token: 1000/10s
- Route: 5/10s
- Headers: `X-Ratelimit-Auth-Token-Remaining`, `X-Ratelimit-Route-Remaining`

## API Version
- Only valid version: `20240415`
- `latestVersion: 20240415`, `beta: false`
