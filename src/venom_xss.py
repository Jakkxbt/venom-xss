#!/usr/bin/env python3
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
from colorama import Fore, Style, init
import os
import json
from pathlib import Path
from datetime import datetime

init(autoreset=True)

BANNER_PATH = os.path.join(os.path.dirname(__file__), "banner.txt")

def print_banner():
    try:
        with open(BANNER_PATH, "r") as f:
            banner = f.readlines()
        colors = [Fore.CYAN, Fore.LIGHTCYAN_EX, Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.GREEN, Fore.LIGHTBLUE_EX]
        for i, line in enumerate(banner):
            color = colors[i % len(colors)]
            print(color + line.rstrip())
        print(Style.RESET_ALL)
    except Exception:
        print(Fore.CYAN + "VENOM XSS SCANNER\n" + Style.RESET_ALL)

def load_payloads():
    payloads = []
    base_dir = os.path.abspath(os.path.dirname(__file__))
    files = ["payloads.txt", "XSSv2.txt"]
    for filename in files:
        path = os.path.join(base_dir, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("//", "#")):
                        payloads.append(line)
        except FileNotFoundError:
            print(Fore.YELLOW + f"[!] Missing {filename}, skipping." + Style.RESET_ALL)
    return list(set(payloads))

def find_forms(url):
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching {url}: {e}" + Style.RESET_ALL)
        return []

def submit_form(form, url, payload):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea"])
    data = {}
    for i in inputs:
        name = i.attrs.get("name")
        if not name:
            continue
        value = payload if i.attrs.get("type") in ("text", "search", "textarea", None) else i.attrs.get("value", "")
        data[name] = value

    target = urljoin(url, action)
    try:
        if method == "post":
            return requests.post(target, data=data, timeout=10)
        else:
            return requests.get(target, params=data, timeout=10)
    except Exception as e:
        print(Fore.RED + f"[!] Error submitting to {target}: {e}" + Style.RESET_ALL)
        return None

def scan_target(url, payloads):
    results = []
    forms = find_forms(url)
    print(Fore.LIGHTGREEN_EX + f"[+] Found {len(forms)} forms on {url}" + Style.RESET_ALL)
    for idx, form in enumerate(forms, 1):
        print(Fore.LIGHTBLUE_EX + f"[>] Testing form #{idx}" + Style.RESET_ALL)
        for payload in payloads:
            resp = submit_form(form, url, payload)
            if resp and payload in resp.text:
                print(Fore.LIGHTMAGENTA_EX + f"[!!!] VULNERABLE form #{idx} with payload: {repr(payload)}" + Style.RESET_ALL)
                results.append({"target": url, "form_number": idx, "payload": payload})
                break  # Stop after first finding per form
    return results

def save_results(results, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    file_path = out_dir / f"venom-xss-results-{ts}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(Fore.CYAN + f"[+] Results saved to {file_path}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="VENOM XSS Scanner (basic form-based)")
    parser.add_argument("--url", help="Single target URL to scan")
    parser.add_argument("--file", help="File containing list of URLs to scan")
    parser.add_argument("--results-dir", default="results", help="Directory to save results")
    args = parser.parse_args()

    print_banner()
    payloads = load_payloads()
    print(Fore.LIGHTYELLOW_EX + f"[VENOM] Loaded {len(payloads)} payloads." + Style.RESET_ALL)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(Fore.RED + f"[!] Could not read {args.file}" + Style.RESET_ALL)

    if not targets:
        print(Fore.RED + "[!] No targets provided. Use --url or --file." + Style.RESET_ALL)
        sys.exit(1)

    all_results = []
    for target in targets:
        print(Fore.CYAN + f"[*] Scanning {target}" + Style.RESET_ALL)
        res = scan_target(target, payloads)
        all_results.extend(res)

    save_results(all_results, args.results_dir)

if __name__ == "__main__":
    main()

