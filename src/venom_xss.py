cat > src/venom_xss.py <<'PY'
#!/usr/bin/env python3
import sys, os, json, argparse, re
from pathlib import Path
from datetime import datetime

# Deps
try:
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    from colorama import Fore, Style, init
except Exception as e:
    print("[!] Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

init(autoreset=True)

# ---------- Paths & discovery ----------
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

BANNER_CANDIDATES = [
    BASE_DIR/"banner.txt",
    BASE_DIR/"VENOM Banner",
    BASE_DIR/"VENOM_banner.txt",
    ROOT_DIR/"banner.txt",
    ROOT_DIR/"VENOM Banner",
    ROOT_DIR/"VENOM_banner.txt",
]

PAYLOAD_CANDIDATE_NAMES = [
    "payloads.txt", "XSSv2.txt",          # old names
    "XSS-Payloads.txt", "XSSv2.1.txt",    # names in your repo
    "xss-payloads.txt", "payloads.XSS.txt"
]
PAYLOAD_CANDIDATES = []
for name in PAYLOAD_CANDIDATE_NAMES:
    PAYLOAD_CANDIDATES.append(BASE_DIR/name)
    PAYLOAD_CANDIDATES.append(ROOT_DIR/name)

def print_banner():
    for p in BANNER_CANDIDATES:
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                colors = [Fore.CYAN, Fore.LIGHTCYAN_EX, Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.GREEN, Fore.LIGHTBLUE_EX]
                for i, line in enumerate(text):
                    print(colors[i % len(colors)] + line + Style.RESET_ALL)
                return
            except Exception:
                pass
    print(Fore.CYAN + "VENOM XSS SCANNER" + Style.RESET_ALL)

def load_payloads() -> list[str]:
    payloads: list[str] = []
    loaded = 0
    seen = set()
    for path in PAYLOAD_CANDIDATES:
        if path.exists() and path.is_file():
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith(("//", "#")):
                            continue
                        # keep as-is (no substitution that nukes characters)
                        payloads.append(line)
                print(Fore.LIGHTYELLOW_EX + f"[VENOM] Loaded payload file: {path}" + Style.RESET_ALL)
                loaded += 1
            except Exception as e:
                print(Fore.YELLOW + f"[!] Could not load {path}: {e}" + Style.RESET_ALL)
    if loaded == 0:
        print(Fore.YELLOW + "[!] No payload files found. Looking for any of: "
              + ", ".join(PAYLOAD_CANDIDATE_NAMES) + Style.RESET_ALL)
    # de-dupe, preserve order
    dedup = []
    for p in payloads:
        if p not in seen:
            dedup.append(p); seen.add(p)
    return dedup

# ---------- HTTP helpers ----------
def http_get(url: str, timeout: int = 10, allow_redirects: bool = True, proxy: str | None = None):
    try:
        kw = {
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "headers": {"User-Agent": "venom-xss/1.0"}
        }
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        return requests.get(url, **kw)
    except Exception:
        return None

def submit_form(form, base_url: str, payload: str, timeout: int = 10, proxy: str | None = None, follow: bool = True):
    action = form.attrs.get("action")
    method = (form.attrs.get("method") or "get").lower()
    inputs = form.find_all(["input", "textarea", "select"])
    data = {}
    for i in inputs:
        name = i.attrs.get("name")
        if not name:
            continue
        itype = (i.attrs.get("type") or "").lower()
        # prefer putting payload into text-ish fields
        if itype in ("text", "search", "email", "url", "tel", "number", "textarea") or i.name == "textarea":
            value = payload
        else:
            value = i.attrs.get("value", payload)  # still try payload if no default
        data[name] = value

    target = urljoin(base_url, action or "")
    try:
        kw = {"timeout": timeout, "headers": {"User-Agent": "venom-xss/1.0"}}
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if method == "post":
            return requests.post(target, data=data, allow_redirects=follow, **kw)
        return requests.get(target, params=data, allow_redirects=follow, **kw)
    except Exception:
        return None

# ---------- Core scan ----------
def find_forms(url: str, timeout: int = 10, proxy: str | None = None, follow: bool = True):
    r = http_get(url, timeout=timeout, allow_redirects=follow, proxy=proxy)
    if not r:
        print(Fore.RED + f"[!] Could not fetch {url}" + Style.RESET_ALL)
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    return soup.find_all("form")

def scan_target(url: str, payloads: list[str], timeout: int, proxy: str | None, follow: bool):
    findings = []
    forms = find_forms(url, timeout=timeout, proxy=proxy, follow=follow)
    print(Fore.LIGHTGREEN_EX + f"[+] Found {len(forms)} forms on {url}" + Style.RESET_ALL)

    for idx, form in enumerate(forms, 1):
        print(Fore.LIGHTBLUE_EX + f"[>] Testing form #{idx}" + Style.RESET_ALL)
        # try payloads until first reflection detected
        for payload in payloads:
            resp = submit_form(form, url, payload, timeout=timeout, proxy=proxy, follow=follow)
            if resp is not None and payload in resp.text:
                print(Fore.LIGHTMAGENTA_EX + f"[!!!] VULNERABLE form #{idx} with payload: {repr(payload)}" + Style.RESET_ALL)
                findings.append({
                    "target": url,
                    "form_number": idx,
                    "payload": payload,
                    "status": getattr(resp, "status_code", None)
                })
                break
    return findings

# ---------- Output ----------
def save_results(rows: list[dict], out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = out_dir / f"venom-xss-results-{ts}.json"
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(Fore.CYAN + f"[+] Results saved to {path}" + Style.RESET_ALL)

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="VENOM XSS Scanner (basic form-based)")
    parser.add_argument("--url", help="Single target URL to scan")
    parser.add_argument("--file", help="File containing list of URLs to scan (one per line)")
    parser.add_argument("--results-dir", default=str(ROOT_DIR / "results"), help="Directory to save results")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--no-follow-redirects", action="store_true")
    args = parser.parse_args()

    print_banner()
    payloads = load_payloads()
    print(Fore.LIGHTYELLOW_EX + f"[VENOM] Loaded {len(payloads)} payloads total." + Style.RESET_ALL)

    # collect targets
    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.file:
        p = Path(args.file)
        if p.exists():
            targets.extend([ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()])
        else:
            print(Fore.RED + f"[!] Could not read {args.file}" + Style.RESET_ALL)

    if not targets:
        print(Fore.RED + "[!] No targets provided. Use --url or --file." + Style.RESET_ALL)
        sys.exit(1)

    all_rows = []
    for t in targets:
        print(Fore.CYAN + f"[*] Scanning {t}" + Style.RESET_ALL)
        all_rows.extend(scan_target(
            t, payloads,
            timeout=args.timeout,
            proxy=args.proxy,
            follow=not args.no_follow_redirects
        ))

    save_results(all_rows, Path(args.results_dir))

if __name__ == "__main__":
    main()
PY

