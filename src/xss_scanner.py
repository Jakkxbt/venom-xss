#!/usr/bin/env python3
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
from colorama import Fore, Style, init
import os

def load_payloads(filenames):
    payloads = []
    for filename in filenames:
        try:
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("//") and not line.startswith("#"):
                        payload = line.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
                        payloads.append(payload)
        except Exception as e:
            print(Fore.YELLOW + f"[!] Could not load {filename}: {e}" + Style.RESET_ALL)
    return payloads



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


def find_forms(url):
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return soup.find_all("form")

def submit_form(form, url, payload):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea"])
    data = {}
    for i in inputs:
        name = i.attrs.get("name")
        if not name:
            continue
        value = payload if i.attrs.get("type") in ("text", "search", "textarea") else i.attrs.get("value", "")
        data[name] = value

    target = urljoin(url, action)
    if method == "post":
        res = requests.post(target, data=data)
    else:
        res = requests.get(target, params=data)
    return res

def scan_xss(url):
    # Always load payloads relative to THIS file's location
    base_dir = os.path.abspath(os.path.dirname(__file__))
    payload_files = [
        os.path.join(base_dir, "payloads.txt"),
        os.path.join(base_dir, "XSSv2.txt"),
    ]
    payloads = load_payloads(payload_files)
    print(Fore.LIGHTYELLOW_EX + f"[VENOM] Loaded {len(payloads)} payloads from both files." + Style.RESET_ALL)

    # The rest of your scan_xss code below...

    ...

    forms = find_forms(url)
    print(Fore.LIGHTGREEN_EX + f"[+] Detected {len(forms)} forms on {url}." + Style.RESET_ALL)
    for idx, form in enumerate(forms, 1):
        print(Fore.LIGHTBLUE_EX + f"[>] Testing form #{idx}" + Style.RESET_ALL)
        vulnerable = False
        for payload in payloads:
            resp = submit_form(form, url, payload)
            if payload in resp.text:
                print(Fore.LIGHTMAGENTA_EX + f"[!] XSS detected in form #{idx} with payload: {repr(payload)}" + Style.RESET_ALL)
                vulnerable = True
        if not vulnerable:
            print(Fore.LIGHTBLACK_EX + f"[-] No XSS detected in form #{idx}" + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="Scan a domain for XSS vulnerabilities (VENOM)")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()

    print_banner()
    scan_xss(args.url)

if __name__ == "__main__":
    main()
