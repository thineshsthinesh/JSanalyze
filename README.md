# JSanalyze

> A fast, concurrent JavaScript reconnaissance tool for bug bounty hunters and penetration testers. Extracts JS files from target URLs, unminifies bundles, and hunts for exposed secrets, API endpoints, and sensitive tokens.

---

## Features

- **Secret Detection** — 25+ patterns covering AWS keys, JWTs, Stripe keys, GitHub tokens, Slack tokens, Discord webhooks, DB connection strings, API keys, and more — each classified by severity (critical / high / medium)
- **Endpoint Extraction** — Pulls API routes, GraphQL paths, versioned endpoints, `fetch()` / `axios` calls, and jQuery AJAX calls from JS bundles
- **Concurrent Scanning** — Scans multiple targets and JS files in parallel via `ThreadPoolExecutor` with configurable thread counts
- **Deep Scan Mode** — Follows JS-within-JS references (`import()`, `require()`, `loadScript()`) to find lazily loaded bundles
- **Auto Unminify** — Detects minified JS and beautifies it before scanning for better pattern coverage
- **Shared Content Cache** — Avoids re-downloading the same CDN-hosted JS file across multiple targets
- **False Positive Filtering** — Skips placeholder values, template variables (`${VAR}`, `{KEY}`), and common dummy strings
- **Structured Output** — Saves per-target results in organized subdirectories with `endpoints.txt`, `secrets.json`, and `js_urls.txt`
- **Combined Report** — Generates a merged `summary.json` and deduplicated `all_secrets.json` across all targets
- **Cookie & Header Support** — Pass session cookies or custom headers for authenticated scans

---

## Installation

```bash
git clone https://github.com/yourusername/jsanalyze.git
cd jsanalyze
pip install -r requirements.txt
```

**Dependencies:**
```
requests
beautifulsoup4
jsbeautifier
tqdm
```

> `curl` must be available in your PATH (used for fetching with compression support).

---

## Usage

### Single target
```bash
python js_extractor.py https://example.com
```

### Scan multiple targets from a file
```bash
python js_extractor.py -f targets.txt
```

### Deep scan (follows JS-within-JS references)
```bash
python js_extractor.py https://example.com --deep
```

### Authenticated scan with cookies and custom headers
```bash
python js_extractor.py https://example.com \
  -c "session=abc123; auth=xyz" \
  -H "Authorization: Bearer <token>"
```

### High-throughput scan with custom thread counts
```bash
python js_extractor.py -f targets.txt --deep --url-threads 10 --js-threads 8
```

### Print results only, skip saving files
```bash
python js_extractor.py https://example.com --no-save
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `url` | — | Single target URL |
| `-f`, `--file` | — | File with target URLs (one per line, `#` comments supported) |
| `--deep` | off | Follow JS-within-JS references for deeper coverage |
| `-o`, `--output` | `js_extracted` | Output directory for results |
| `--url-threads` | `5` | Concurrent target URLs to scan |
| `--js-threads` | `8` | Concurrent JS file downloads per target |
| `-c`, `--cookies` | — | Cookie string: `name=value; name2=value2` |
| `-H`, `--header` | — | Custom request header (repeatable): `Name: Value` |
| `--no-save` | off | Print summary to stdout only, don't write files |

---

## Output Structure

```
js_extracted/
├── summary.json              ← Combined scan overview (all targets)
├── all_js_urls.txt           ← All unique JS files discovered
├── all_endpoints.txt         ← All unique endpoints across targets
├── all_secrets.json          ← Deduplicated secrets across targets
│
└── example.com/
    ├── js_urls.txt           ← JS files found on this target
    ├── endpoints.txt         ← Endpoints extracted from JS
    ├── endpoints.json
    ├── secrets.txt           ← Human-readable secrets report
    └── secrets.json          ← Machine-readable secrets with context
```

---

## Secret Severity Levels

| Severity | Examples |
|----------|---------|
| 🔴 Critical | AWS keys, GitHub tokens, Stripe live keys, JWTs, DB URIs, SSH/RSA private keys, Slack tokens, passwords |
| 🟠 High | Stripe publishable keys, Redis URIs, API keys, access tokens, auth tokens |
| 🟡 Medium | Stripe test keys, reCAPTCHA site keys |

---

## Example Output

```
======================================================================
JS EXTRACTOR  |  targets=3  deep=True  threads=5×8
======================================================================

  [1/3] https://app.example.com  →  12 JS, 47 endpoints, 2 secrets  ✓
  [2/3] https://api.example.com  →  4 JS, 19 endpoints, 0 secrets   ✓
  [3/3] https://cdn.example.com  →  8 JS, 31 endpoints, 1 secret    ✓

======================================================================
RESULTS  |  JS files: 24  |  Endpoints: 97  |  Secrets: 3
======================================================================

🔴 CRITICAL (2):
    [AWS Access Key ID] AKIA4EXAMPLE1234XXXX
      └─ https://app.example.com/static/config.js
    [JWT Token] eyJhbGciOiJIUzI1NiJ9.eyJzdWIiO...
      └─ https://app.example.com/static/auth.js

🟠 HIGH (1):
    [API Key] sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx
      └─ https://cdn.example.com/bundle.min.js
```

---

## Responsible Use

JSanalyze is intended for **authorized security testing only** — bug bounty programs, penetration testing engagements, and security research on systems you have explicit permission to test. Unauthorized use against systems you do not own or have written permission to test may violate computer fraud laws in your jurisdiction.

---

## License

MIT License — free to use, modify, and distribute with attribution.
