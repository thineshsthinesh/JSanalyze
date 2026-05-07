#!/usr/bin/env python3
"""
JS Link Extractor and Analyzer Tool
Fetches JS links from one or more URLs, unminifies, and scans for endpoints and secrets.
Supports scanning a list of URLs from a file concurrently.
"""

import subprocess
import re
import os
import json
import hashlib
import gzip
import zlib
import time
import argparse
import sys
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from collections import defaultdict

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:
        def __init__(self, total=0, desc="", unit=""):
            self.total = total
            self.desc = desc
            self._n = 0
        def update(self, n=1):
            self._n += n
            pct = int(self._n / self.total * 100) if self.total else 0
            print(f"\r  {self.desc}: {self._n}/{self.total} ({pct}%)", end="", flush=True)
        def __enter__(self): return self
        def __exit__(self, *a):
            print()


# ─────────────────────────────────────────────
# HTTP / FETCH
# ─────────────────────────────────────────────

def fetch_with_curl(url: str, headers: dict = None, timeout: int = 20) -> Optional[str]:
    """Fetch URL content using curl with decompression and custom headers."""
    cmd = [
        "curl", "-s", "-L", "-k", "--compressed",
        "--max-time", str(timeout),
        "--retry", "2",
        "--retry-delay", "1",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate, br",
        "-H", "Connection: keep-alive",
    ]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        if result.returncode == 0 and result.stdout:
            for decoder in [
                lambda b: b.decode("utf-8"),
                lambda b: gzip.decompress(b).decode("utf-8", errors="ignore"),
                lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS).decode("utf-8", errors="ignore"),
                lambda b: b.decode("utf-8", errors="ignore"),
            ]:
                try:
                    return decoder(result.stdout)
                except Exception:
                    continue
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return None


def fetch_js_content(url: str, retries: int = 3, backoff: float = 1.5) -> Optional[str]:
    """Fetch JavaScript content with exponential backoff retries."""
    cmd = [
        "curl", "-s", "-L", "-k", "--compressed",
        "--max-time", "15",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ]
    for attempt in range(retries):
        try:
            result = subprocess.run(cmd + [url], capture_output=True, timeout=20)
            if result.returncode == 0 and result.stdout:
                for decoder in [
                    lambda b: b.decode("utf-8"),
                    lambda b: gzip.decompress(b).decode("utf-8", errors="ignore"),
                    lambda b: b.decode("utf-8", errors="ignore"),
                ]:
                    try:
                        return decoder(result.stdout)
                    except Exception:
                        continue
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(backoff ** attempt)
    return None


# ─────────────────────────────────────────────
# URL UTILITIES
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def clean_url(url: str, base_url: str) -> Optional[str]:
    """Resolve and normalize a URL relative to a base."""
    if not url:
        return None
    url = url.strip()
    url = re.sub(r"^/\\\\+/", "/", url)
    url = re.sub(r"\\\\", "/", url)
    full_url = urljoin(base_url, url)
    full_url = urldefrag(full_url)[0]
    parsed = urlparse(full_url)
    if "//" in parsed.path and parsed.path != "//":
        parsed = parsed._replace(path=re.sub(r"/+", "/", parsed.path))
        full_url = parsed.geturl()
    return full_url if parsed.scheme in ("http", "https") else None


def is_js_url(url: str) -> bool:
    return bool(url) and (url.endswith(".js") or ".js?" in url or "/js/" in url)


def load_urls_from_file(filepath: str) -> List[str]:
    """Read URLs from a file (one per line, # comments ignored)."""
    urls = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(normalize_url(line))
    except FileNotFoundError:
        print(f"[!] URL file not found: {filepath}")
        sys.exit(1)
    return urls


# ─────────────────────────────────────────────
# JS EXTRACTION
# ─────────────────────────────────────────────

_JS_HTML_PATTERNS = [
    r'src=["\']([^"\']+\.js[^"\']*)["\']',
    r'href=["\']([^"\']+\.js[^"\']*)["\']',
    r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?',
    r'/[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?',
    r'wp-includes/js/[^"\']+\.js',
    r'wp-content/[^"\']+\.js',
]

_JS_IN_JS_PATTERNS = [
    r'import\(["\']([^"\']+\.js[^"\']*)["\']',
    r'require\(["\']([^"\']+\.js[^"\']*)["\']',
    r'import\s+.*?\s+from\s+["\']([^"\']+\.js[^"\']*)["\']',
    r'src=["\']([^"\']+\.js[^"\']*)["\']',
    r'loadScript\(["\']([^"\']+\.js[^"\']*)["\']',
]


def extract_js_urls_from_html(html: str, base_url: str) -> Set[str]:
    """Extract all JS file URLs from HTML using BeautifulSoup + regex."""
    js_urls: Set[str] = set()

    # BeautifulSoup pass
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            cleaned = clean_url(tag["src"], base_url)
            if cleaned and is_js_url(cleaned):
                js_urls.add(cleaned)
    except Exception:
        pass

    # Regex pass
    for pattern in _JS_HTML_PATTERNS:
        for match in re.findall(pattern, html, re.IGNORECASE):
            val = match[0] if isinstance(match, tuple) else match
            cleaned = clean_url(val, base_url)
            if cleaned and is_js_url(cleaned):
                js_urls.add(cleaned)

    return js_urls


def extract_js_refs_from_js(content: str, base_url: str) -> Set[str]:
    """Find JS file references embedded inside a JS file."""
    refs: Set[str] = set()
    for pattern in _JS_IN_JS_PATTERNS:
        for match in re.findall(pattern, content, re.IGNORECASE):
            val = (match[0] if isinstance(match, tuple) else match).strip("\"'")
            cleaned = clean_url(val, base_url)
            if cleaned and is_js_url(cleaned):
                refs.add(cleaned)
    return refs


# ─────────────────────────────────────────────
# UNMINIFY
# ─────────────────────────────────────────────

def is_minified(content: str) -> bool:
    if not content or len(content) < 100:
        return False
    lines = content.split("\n")
    avg_len = len(content) / max(len(lines), 1)
    return avg_len > 500 or (len(lines) < 20 and len(content) > 10_000)


def unminify_js(content: str) -> str:
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 4
        opts.preserve_newlines = True
        opts.max_preserve_newlines = 2
        return jsbeautifier.beautify(content, opts)
    except Exception:
        return content


# ─────────────────────────────────────────────
# ENDPOINT SCANNING
# ─────────────────────────────────────────────

_ENDPOINT_PATTERNS = [
    r'["\'](https?://[^"\']{5,})["\']',
    r'["\'](/api/[\w/.\-?=&%#@!]+)["\']',
    r'["\'](/v\d+/[\w/.\-?=&%#@!]+)["\']',
    r'["\'](/graphql(?:/[^\s"\']*)?)["\']',
    r'["\'](/rest/[\w/.\-?=&%]+)["\']',
    r'["\'](/wp-json/[\w/.\-?=&%]+)["\']',
    r'fetch\(\s*["\']([^"\']+)["\']',
    r'axios\.(?:get|post|put|delete|patch|head|options)\(\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseURL|apiURL)\s*[=:]\s*["\']([^"\']{5,})["\']',
    r'\$\.(?:get|post|ajax)\(\s*["\']([^"\']+)["\']',
]

_ENDPOINT_BLACKLIST = re.compile(
    r"(javascript:|data:|blob:|#|\.png|\.jpg|\.gif|\.svg|\.css|\.woff|\.ttf|\.ico)",
    re.IGNORECASE,
)


def scan_for_endpoints(content: str) -> Set[str]:
    endpoints: Set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in re.findall(pattern, content, re.IGNORECASE):
            val = (match[0] if isinstance(match, tuple) else match).strip("\"'").split("?")[0]
            if val and len(val) > 3 and not _ENDPOINT_BLACKLIST.search(val):
                endpoints.add(val)
    return endpoints


# ─────────────────────────────────────────────
# SECRET SCANNING
# ─────────────────────────────────────────────

# (pattern, label, severity, require_capture_group)
_SECRET_PATTERNS = [
    # Cloud providers
    (r'\bAKIA[0-9A-Z]{16}\b',                                         "AWS Access Key ID",              "critical"),
    (r'\bASIA[0-9A-Z]{16}\b',                                         "AWS Temp Access Key",            "critical"),
    (r'\bAIza[0-9A-Za-z\-_]{35}\b',                                   "Google API Key",                 "critical"),
    # GitHub
    (r'\bghp_[0-9a-zA-Z]{36}\b',                                      "GitHub Personal Token",          "critical"),
    (r'\bgho_[0-9a-zA-Z]{36}\b',                                      "GitHub OAuth Token",             "critical"),
    (r'\bghs_[0-9a-zA-Z]{36}\b',                                      "GitHub Server Token",            "critical"),
    # Slack / Discord
    (r'\bxox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b',                   "Slack Token",                    "critical"),
    (r'https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+',    "Discord Webhook",                "critical"),
    # Stripe
    (r'\bsk_live_[0-9a-zA-Z]{24,}\b',                                 "Stripe Live Secret Key",         "critical"),
    (r'\bpk_live_[0-9a-zA-Z]{24,}\b',                                 "Stripe Live Publishable Key",    "high"),
    (r'\bsk_test_[0-9a-zA-Z]{24,}\b',                                 "Stripe Test Secret Key",         "medium"),
    # JWT
    (r'\beyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b',"JWT Token",                      "critical"),
    # Private keys
    (r'-----BEGIN RSA PRIVATE KEY-----',                               "RSA Private Key",                "critical"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----',                           "SSH Private Key",                "critical"),
    (r'-----BEGIN PRIVATE KEY-----',                                   "Private Key",                    "critical"),
    # DB URIs
    (r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}',                          "MongoDB URI",                    "critical"),
    (r'postgresql://[^\s"\'<>]{10,}',                                  "PostgreSQL URI",                 "critical"),
    (r'mysql://[^\s"\'<>]{10,}',                                       "MySQL URI",                      "critical"),
    (r'redis://[^\s"\'<>]{10,}',                                       "Redis URI",                      "high"),
    # Generic secrets with capture groups (value extracted)
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',      "Password",                       "critical"),
    (r'(?:secret|private[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']',  "Secret",                         "critical"),
    (r'api[_-]?key\s*[:=]\s*["\']([^"\']{10,})["\']',                "API Key",                        "high"),
    (r'client[_-]?secret\s*[:=]\s*["\']([^"\']{10,})["\']',          "Client Secret",                  "critical"),
    (r'access[_-]?token\s*[:=]\s*["\']([^"\']{10,})["\']',           "Access Token",                   "high"),
    (r'auth[_-]?token\s*[:=]\s*["\']([^"\']{10,})["\']',             "Auth Token",                     "high"),
    # reCAPTCHA
    (r'"sitekey"\s*:\s*"([^"]+)"',                                    "reCAPTCHA Site Key",             "medium"),
]

# Values that are almost certainly false positives
_FP_VALUES = frozenset([
    "true", "false", "null", "undefined", "none", "string", "number",
    "boolean", "object", "function", "your_key_here", "your_secret_here",
    "xxx", "yyy", "zzz", "example", "placeholder", "changeme",
])


def scan_for_secrets(content: str, source_url: str) -> List[Dict]:
    found = []
    seen_hashes: Set[str] = set()

    for pattern, label, severity in _SECRET_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            # Use first capture group if present, else full match
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()
            if not value or len(value) < 6:
                continue
            if value.lower() in _FP_VALUES:
                continue
            # Skip obvious template variables like ${VAR} or {VAR}
            if re.match(r"^[\$\{]", value) or re.match(r"^\{[A-Z_]+\}$", value):
                continue

            dedup_key = hashlib.md5(f"{label}:{value}".encode()).hexdigest()
            if dedup_key in seen_hashes:
                continue
            seen_hashes.add(dedup_key)

            # Get surrounding context (60 chars each side)
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            context = content[start:end].replace("\n", " ").strip()

            found.append({
                "id":       hashlib.md5(f"{source_url}:{label}:{value}".encode()).hexdigest(),
                "type":     label,
                "severity": severity,
                "value":    (value[:80] + "...") if len(value) > 80 else value,
                "context":  context,
                "file":     source_url,
            })

    return found


# ─────────────────────────────────────────────
# PER-URL SCANNING LOGIC
# ─────────────────────────────────────────────

def scan_single_target(
    url: str,
    headers: dict,
    deep: bool,
    js_threads: int,
    shared_js_cache: dict,         # {js_url: content} – shared across targets
    cache_lock,
) -> Dict:
    """
    Scan a single target URL: fetch HTML, extract JS, process each JS file.
    Returns a results dict for this target.
    """
    result = {
        "url": url,
        "js_urls": [],
        "endpoints": set(),
        "secrets": [],
        "error": None,
    }

    # Fetch HTML
    html = fetch_with_curl(url, headers)
    if not html:
        result["error"] = "Failed to fetch page"
        return result

    # Extract JS URLs
    js_urls = extract_js_urls_from_html(html, url)

    # Deep scan
    if deep and js_urls:
        additional: Set[str] = set()
        to_scan = list(js_urls)
        with ThreadPoolExecutor(max_workers=js_threads) as ex:
            futs = {ex.submit(fetch_js_content, ju): ju for ju in to_scan}
            for fut in as_completed(futs):
                content = fut.result()
                if content:
                    refs = extract_js_refs_from_js(content, futs[fut])
                    additional.update(refs - js_urls)
                    # Cache content
                    with cache_lock:
                        shared_js_cache.setdefault(futs[fut], content)
        js_urls.update(additional)

    js_urls = sorted(u for u in js_urls if is_js_url(u))
    result["js_urls"] = js_urls

    # Process JS files
    def process_js(js_url: str):
        # Check cache first
        with cache_lock:
            content = shared_js_cache.get(js_url)
        if content is None:
            content = fetch_js_content(js_url)
            if content:
                with cache_lock:
                    shared_js_cache[js_url] = content
        if not content:
            return set(), []
        if is_minified(content):
            content = unminify_js(content)
        return scan_for_endpoints(content), scan_for_secrets(content, js_url)

    with ThreadPoolExecutor(max_workers=js_threads) as ex:
        futs = {ex.submit(process_js, ju): ju for ju in js_urls}
        with tqdm(total=len(futs), desc=f"  JS files ({urlparse(url).netloc})", unit="file") as pbar:
            for fut in as_completed(futs):
                try:
                    eps, secs = fut.result()
                    result["endpoints"].update(eps)
                    result["secrets"].extend(secs)
                except Exception:
                    pass
                pbar.update(1)

    return result


# ─────────────────────────────────────────────
# OUTPUT / SAVING
# ─────────────────────────────────────────────

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def print_secrets_summary(secrets: List[Dict], label: str = ""):
    if not secrets:
        return
    print(f"\n{'='*70}")
    print(f"SECRETS SUMMARY{' — ' + label if label else ''}")
    print(f"{'='*70}")
    for sev in SEVERITY_ORDER:
        subset = [s for s in secrets if s["severity"] == sev]
        if subset:
            icon = SEVERITY_ICON.get(sev, "•")
            print(f"\n{icon} {sev.upper()} ({len(subset)}):")
            for s in subset[:10]:
                print(f"    [{s['type']}] {s['value']}")
                print(f"      └─ {s['file']}")
            if len(subset) > 10:
                print(f"    … and {len(subset) - 10} more")


def save_target_results(output_dir: str, target_result: Dict):
    """Save results for a single target into its own subdirectory."""
    netloc = urlparse(target_result["url"]).netloc.replace(":", "_")
    target_dir = os.path.join(output_dir, netloc)
    os.makedirs(target_dir, exist_ok=True)

    # JS URLs
    with open(os.path.join(target_dir, "js_urls.txt"), "w") as f:
        f.write("\n".join(sorted(target_result["js_urls"])) + "\n")

    # Endpoints
    endpoints = sorted(target_result["endpoints"])
    if endpoints:
        with open(os.path.join(target_dir, "endpoints.txt"), "w") as f:
            f.write("\n".join(endpoints) + "\n")
        with open(os.path.join(target_dir, "endpoints.json"), "w") as f:
            json.dump(endpoints, f, indent=2)

    # Secrets
    secrets = target_result["secrets"]
    if secrets:
        with open(os.path.join(target_dir, "secrets.json"), "w") as f:
            json.dump(secrets, f, indent=2)
        with open(os.path.join(target_dir, "secrets.txt"), "w") as f:
            for sev in SEVERITY_ORDER:
                subset = [s for s in secrets if s["severity"] == sev]
                if subset:
                    f.write(f"\n[{sev.upper()}] — {len(subset)} finding(s)\n")
                    f.write("-" * 50 + "\n")
                    for s in subset:
                        f.write(f"  Type   : {s['type']}\n")
                        f.write(f"  Value  : {s['value']}\n")
                        f.write(f"  File   : {s['file']}\n")
                        f.write(f"  Context: {s['context']}\n")
                        f.write(f"  ID     : {s['id']}\n")
                        f.write("-" * 50 + "\n")

    return target_dir


def save_combined_results(output_dir: str, all_results: List[Dict]):
    """Save a merged report across all targets."""
    os.makedirs(output_dir, exist_ok=True)

    all_js: Set[str] = set()
    all_endpoints: Set[str] = set()
    all_secrets: List[Dict] = []

    for r in all_results:
        all_js.update(r["js_urls"])
        all_endpoints.update(r["endpoints"])
        all_secrets.extend(r["secrets"])

    # Deduplicate secrets by id
    seen_ids: Set[str] = set()
    unique_secrets = []
    for s in all_secrets:
        if s["id"] not in seen_ids:
            seen_ids.add(s["id"])
            unique_secrets.append(s)

    with open(os.path.join(output_dir, "all_js_urls.txt"), "w") as f:
        f.write("\n".join(sorted(all_js)) + "\n")

    if all_endpoints:
        with open(os.path.join(output_dir, "all_endpoints.txt"), "w") as f:
            f.write("\n".join(sorted(all_endpoints)) + "\n")
        with open(os.path.join(output_dir, "all_endpoints.json"), "w") as f:
            json.dump(sorted(list(all_endpoints)), f, indent=2)

    if unique_secrets:
        with open(os.path.join(output_dir, "all_secrets.json"), "w") as f:
            json.dump(unique_secrets, f, indent=2)

    # Summary JSON
    summary = {
        "total_targets":   len(all_results),
        "total_js_files":  len(all_js),
        "total_endpoints": len(all_endpoints),
        "total_secrets":   len(unique_secrets),
        "secrets_by_severity": {
            sev: len([s for s in unique_secrets if s["severity"] == sev])
            for sev in SEVERITY_ORDER
        },
        "targets": [
            {
                "url":       r["url"],
                "js_files":  len(r["js_urls"]),
                "endpoints": len(r["endpoints"]),
                "secrets":   len(r["secrets"]),
                "error":     r.get("error"),
            }
            for r in all_results
        ],
    }
    with open(os.path.join(output_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    return summary, unique_secrets


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JS Link Extractor — finds JavaScript files, endpoints, and secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single URL
  python js_extractor.py https://example.com

  # Scan a list of URLs from a file (one per line)
  python js_extractor.py -f urls.txt

  # Deep scan (follows JS-within-JS references)
  python js_extractor.py https://example.com --deep

  # Scan file with deep scan, 10 concurrent targets, 8 JS threads
  python js_extractor.py -f urls.txt --deep --url-threads 10 --js-threads 8

  # With cookies / custom headers
  python js_extractor.py https://example.com -c "session=abc" -H "Authorization: Bearer token"

  # Save output to custom directory
  python js_extractor.py -f urls.txt -o ./results
        """,
    )

    # Target selection (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("url", nargs="?",  help="Single target URL")
    target_group.add_argument("-f", "--file",    help="File with target URLs (one per line)")

    # Options
    parser.add_argument("--deep",          action="store_true", help="Deep scan: follow JS-within-JS references")
    parser.add_argument("-o", "--output",  default="js_extracted", help="Output directory (default: js_extracted)")
    parser.add_argument("--url-threads",   type=int, default=5,  help="Concurrent target URLs (default: 5)")
    parser.add_argument("--js-threads",    type=int, default=8,  help="Concurrent JS downloads per target (default: 8)")
    parser.add_argument("-c", "--cookies", help="Cookies: name1=value1; name2=value2")
    parser.add_argument("-H", "--header",  action="append", help="Custom header: Name: Value")
    parser.add_argument("--no-save",       action="store_true", help="Print summary only, don't save files")

    args = parser.parse_args()

    # Build headers dict
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    if args.cookies:
        parts = [p.strip() for p in args.cookies.split(";") if "=" in p]
        headers["Cookie"] = "; ".join(parts)

    # Collect target URLs
    if args.file:
        urls = load_urls_from_file(args.file)
        if not urls:
            print("[!] No URLs found in file.")
            sys.exit(1)
        print(f"[+] Loaded {len(urls)} URLs from {args.file}")
    else:
        urls = [normalize_url(args.url)]

    print(f"\n{'='*70}")
    print(f"JS EXTRACTOR  |  targets={len(urls)}  deep={args.deep}  threads={args.url_threads}×{args.js_threads}")
    print(f"{'='*70}\n")

    # Shared JS content cache (avoids re-downloading the same CDN file for every target)
    import threading
    shared_js_cache: dict = {}
    cache_lock = threading.Lock()

    all_results: List[Dict] = []

    # Run targets concurrently
    if len(urls) == 1:
        # Single target: run directly (cleaner output)
        print(f"[*] Scanning {urls[0]} ...")
        r = scan_single_target(urls[0], headers, args.deep, args.js_threads, shared_js_cache, cache_lock)
        all_results.append(r)
    else:
        with ThreadPoolExecutor(max_workers=args.url_threads) as ex:
            futs = {
                ex.submit(scan_single_target, u, headers, args.deep, args.js_threads, shared_js_cache, cache_lock): u
                for u in urls
            }
            completed = 0
            for fut in as_completed(futs):
                completed += 1
                u = futs[fut]
                try:
                    r = fut.result()
                    status = "✓" if not r["error"] else f"✗ {r['error']}"
                    print(f"  [{completed}/{len(urls)}] {u}  →  "
                          f"{len(r['js_urls'])} JS, "
                          f"{len(r['endpoints'])} endpoints, "
                          f"{len(r['secrets'])} secrets  {status}")
                    all_results.append(r)
                except Exception as e:
                    print(f"  [{completed}/{len(urls)}] {u}  →  ERROR: {e}")
                    all_results.append({"url": u, "js_urls": [], "endpoints": set(), "secrets": [], "error": str(e)})

    # Print combined summary
    total_js = sum(len(r["js_urls"]) for r in all_results)
    total_ep = sum(len(r["endpoints"]) for r in all_results)
    all_secs = [s for r in all_results for s in r["secrets"]]

    print(f"\n{'='*70}")
    print(f"RESULTS  |  JS files: {total_js}  |  Endpoints: {total_ep}  |  Secrets: {len(all_secs)}")
    print(f"{'='*70}")

    if all_secs:
        print_secrets_summary(all_secs, label="all targets")

    # Save results
    if not args.no_save:
        print(f"\n[*] Saving results to: {args.output}/")
        for r in all_results:
            if r["js_urls"] or r["endpoints"] or r["secrets"]:
                target_dir = save_target_results(args.output, r)
                print(f"    ✓ {r['url']}  →  {target_dir}/")
        summary, unique_secrets = save_combined_results(args.output, all_results)
        print(f"\n[+] Combined report saved to: {args.output}/")
        print(f"      summary.json       — scan overview")
        print(f"      all_js_urls.txt    — {len(set(j for r in all_results for j in r['js_urls']))} unique JS files")
        if total_ep:
            print(f"      all_endpoints.txt  — {len(set(e for r in all_results for e in r['endpoints']))} unique endpoints")
        if unique_secrets:
            print(f"      all_secrets.json   — {len(unique_secrets)} unique secrets")

    print(f"\n{'='*70}")
    print("SCAN COMPLETE")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
