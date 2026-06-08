#!/usr/bin/env python3
"""Comprehensive JS analysis: URLs, secrets, config, GraphQL, etc."""
import os, re, json, sys
from collections import Counter
from urllib.parse import urlparse

OUT = "/workspaces/linux/analysis"
os.makedirs(OUT, exist_ok=True)

ALL_DIRS = ["/workspaces/linux/js_files", "/workspaces/linux/new_js_files"]

def all_js_files():
    seen_content = set()
    for d in ALL_DIRS:
        for root, dirs, files in os.walk(d):
            for f in files:
                if f.endswith(".js"):
                    yield os.path.join(root, f)

def dedup(files):
    """Yield only unique files based on content hash."""
    seen = set()
    for fp in files:
        try:
            with open(fp, "rb") as fh:
                h = hash(fh.read(1024 * 1024))  # first 1MB
            if h not in seen:
                seen.add(h)
                yield fp
        except:
            pass

files = list(all_js_files())
print(f"Total JS files: {len(files)}")

unique = list(dedup(files))
print(f"Unique files:   {len(unique)}")

# ── 1. ALL URLS ──
print("\n[1] Extracting URLs...")
url_pattern = re.compile(rb'https?://[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+')
third_party_domains = {
    "maps.googleapis.com", "www.googletagmanager.com", "www.google-analytics.com",
    "js.sentry-cdn.com", "cdn.plaid.com", "bat.bing.com", "t.co",
    "cdnjs.cloudflare.com", "ajax.googleapis.com", "fonts.googleapis.com",
    "code.highcharts.com", "unpkg.com", "cdn.amplitude.com",
    "www.linkedin.com", "platform.twitter.com", "www.instagram.com",
    "pinterest.com", "youtube.com", "vimeo.com", "gravatar.com",
    "googlesyndication.com", "doubleclick.net", "github.com",
    "www.npmjs.com", "w3.org", "schema.org", "mozilla.org", "whatwg.org",
}

all_urls = set()
ld_urls = set()
ws_urls = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            data = fh.read()
        for m in url_pattern.finditer(data):
            url = m.group().decode("utf-8", errors="replace")
            all_urls.add(url)
            dom = urlparse(url).netloc.lower()
            if "launchdarkly" in dom:
                ld_urls.add(url)
            if url.startswith("ws"):
                ws_urls.add(url)
    except Exception as e:
        print(f"  Error {fp}: {e}", file=sys.stderr)

# Filter 3rd party
non_3p = sorted(u for u in all_urls if urlparse(u).netloc.lower() not in third_party_domains)
with open(f"{OUT}/urls_all.txt", "w") as f:
    f.write("\n".join(non_3p) + "\n")
with open(f"{OUT}/ld_urls.txt", "w") as f:
    f.write("\n".join(sorted(ld_urls)) + "\n")
with open(f"{OUT}/websocket_urls.txt", "w") as f:
    f.write("\n".join(sorted(ws_urls)) + "\n")

print(f"  Total unique URLs:     {len(all_urls)}")
print(f"  Non-3rd-party URLs:    {len(non_3p)}")
print(f"  LD-specific URLs:      {len(ld_urls)}")
print(f"  WebSocket URLs:        {len(ws_urls)}")

# ── 2. SECRETS ──
print("\n[2] Extracting secrets/keys/tokens...")
secret_patterns = {
    "SDK Key (sdk-)":      rb'sdk-[a-zA-Z0-9]{20,50}',
    "API Key (api-)":      rb'api-[a-zA-Z0-9]{20,50}',
    "Mobile Key (mob-)":   rb'mob-[a-zA-Z0-9]{20,50}',
    "Stripe (sk_)":        rb'sk_[a-zA-Z0-9]{20,}',
    "Stripe (pk_)":        rb'pk_[a-zA-Z0-9]{20,}',
    "GitHub Token":        rb'gh[puo]_[a-zA-Z0-9]{36}',
    "AWS Access Key":      rb'AKIA[0-9A-Z]{16}',
    "JWT":                 rb'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
    "Google API Key":      rb'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":         rb'xox[abposr]-[a-zA-Z0-9\-]{10,}',
}

all_secrets = {}
for name, pat in secret_patterns.items():
    found = set()
    for fp in unique:
        try:
            with open(fp, "rb") as fh:
                data = fh.read()
            for m in pat.finditer(data):
                found.add(m.group().decode("utf-8", errors="replace"))
        except:
            pass
    if found:
        all_secrets[name] = sorted(found)

with open(f"{OUT}/secrets_raw.txt", "w") as f:
    for name, vals in all_secrets.items():
        f.write(f"--- {name} ({len(vals)} found) ---\n")
        for v in vals:
            f.write(f"{v}\n")
        f.write("\n")

if all_secrets:
    for name, vals in all_secrets.items():
        print(f"  {name}: {len(vals)} found")
        for v in vals[:5]:
            print(f"    {v}")
        if len(vals) > 5:
            print(f"    ... and {len(vals)-5} more")
else:
    print("  No secrets found")

# ── 3. GRAPHQL / API PATHS ──
print("\n[3] Extracting API paths and patterns...")
api_pat = re.compile(rb'(/api/[a-zA-Z0-9_\-/.]+|/graphql|/v[0-9]+/[a-zA-Z0-9_\-/]+)')
api_paths = Counter()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            for line in fh:
                for m in api_pat.finditer(line):
                    p = m.group(1).decode("utf-8", errors="replace")
                    if len(p) > 5:
                        api_paths[p] += 1
    except:
        pass

with open(f"{OUT}/graphql_endpoints.txt", "w") as f:
    for p, c in api_paths.most_common(200):
        f.write(f"{p} (count: {c})\n")

print(f"  Found {len(api_paths)} unique API paths")
for p, c in api_paths.most_common(30):
    print(f"    {p} (x{c})")

# ── 4. FEATURE FLAG KEYS ──
print("\n[4] Extracting feature flag keys...")
flag_pat = re.compile(rb'["\'`]([a-z]+[-_][a-z]+[-_][a-z0-9_\-]+)["\'`]')
# Heuristic: flag keys tend to be dot-separated, underscore-separated, hyphen-separated
# and appear near known flag-related terms
flag_terms = [b'flag', b'toggle', b'feature', b'variation', b'launchdarkly']
flag_keys = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            data = fh.read()
        # Check if file mentions flag-related terms
        if not any(t in data.lower() for t in flag_terms):
            continue
        for m in flag_pat.finditer(data):
            k = m.group(1).decode("utf-8", errors="replace")
            # Filter: likely flag keys are lowercase with separators, 10-60 chars
            if 8 <= len(k) <= 60 and not k.startswith("http") and not k.startswith("www"):
                flag_keys.add(k)
    except:
        pass

with open(f"{OUT}/flag_keys.txt", "w") as f:
    for k in sorted(flag_keys)[:500]:
        f.write(f"{k}\n")

print(f"  Found {len(flag_keys)} potential flag keys (showing first 50)")
for k in sorted(flag_keys)[:50]:
    print(f"    {k}")

# ── 5. GRAPHQL QUERIES/MUTATIONS ──
print("\n[5] Extracting GraphQL operations...")
gql_pat = re.compile(rb'(query|mutation|subscription)\s+(\w+)\s*[({]', re.IGNORECASE)
gql_ops = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            for line in fh:
                for m in gql_pat.finditer(line):
                    gql_ops.add(f"{m.group(1).decode()} {m.group(2).decode()}")
    except:
        pass

with open(f"{OUT}/graphql_operations.txt", "w") as f:
    for op in sorted(gql_ops):
        f.write(f"{op}\n")

print(f"  Found {len(gql_ops)} GraphQL operations")
for op in sorted(gql_ops)[:50]:
    print(f"    {op}")

# ── 6. ENVIRONMENT / PROJECT / ORG KEYS ──
print("\n[6] Extracting environment/project/org identifiers...")
env_pat = re.compile(rb'["\'`]([a-zA-Z0-9_]{8,64})["\'`]')
ld_context_terms = [b'clientSideID', b'environment', b'project', b'organization',
                     b'orgKey', b'projectKey', b'envKey', b'sdkKey', b'mobileKey']
ld_ids = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            data = fh.read()
        if not any(t in data for t in ld_context_terms):
            continue
        # Look for key=value patterns
        for m in re.finditer(rb'["\'`]([a-zA-Z]+(?:Key|ID|Id|id))["\'`]\s*[:=]\s*["\'`]([^"\'`]+)["\'`]', data):
            k = m.group(1).decode()
            v = m.group(2).decode()
            ld_ids.add(f"{k}: {v}")
    except:
        pass

with open(f"{OUT}/ld_ids.txt", "w") as f:
    for item in sorted(ld_ids):
        f.write(f"{item}\n")

print(f"  Found {len(ld_ids)} LD identifiers")
for item in sorted(ld_ids)[:50]:
    print(f"    {item}")

# ── 7. SERVICE WORKERS ──
print("\n[7] Extracting service worker references...")
sw_pat = re.compile(rb'["\'`]([^"\']+\.worker\.js)["\'`]')
sw_refs = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            data = fh.read()
        for m in sw_pat.finditer(data):
            sw_refs.add(m.group(1).decode())
    except:
        pass

with open(f"{OUT}/service_workers.txt", "w") as f:
    for sw in sorted(sw_refs):
        f.write(f"{sw}\n")

print(f"  Found {len(sw_refs)} service worker references")
for sw in sorted(sw_refs):
    print(f"    {sw}")

# ── 8. INTERESTING STRINGS (config objects, etc.) ──
print("\n[8] Extracting config/JSON objects...")
# Look for JSON-like objects in strings
json_pat = re.compile(rb'["\'`]({[^}]+})["\'`]')
configs = set()
for fp in unique:
    try:
        with open(fp, "rb") as fh:
            data = fh.read()
        # Only if file looks like config
        if b'config' not in data.lower() and b'setting' not in data.lower():
            continue
        for m in json_pat.finditer(data):
            try:
                obj = json.loads(m.group(1))
                if isinstance(obj, dict) and len(obj) <= 20:
                    configs.add(json.dumps(obj, sort_keys=True))
            except:
                pass
    except:
        pass

with open(f"{OUT}/config_objects.txt", "w") as f:
    for c in sorted(configs)[:200]:
        f.write(f"{c}\n")

print(f"  Found {len(configs)} config objects (showing first 30)")
for c in sorted(configs)[:30]:
    print(f"    {c[:200]}")

print("\n=== ANALYSIS COMPLETE ===")
print(f"Output files in: {OUT}/")
