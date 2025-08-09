# venom-xss
# VENOM XSS Scanner

A cyberpunk-themed Python CLI tool to scan websites for XSS vulnerabilities.

## Install

Clone the repo, then:

pip install -r requirements.txt


rm -rf venom-xss 
git clone https://github.com/Jakkxbt/venom-xss.git
cd venom-xss

# Single URL
python3 src/venom_xss.py --url https://example.com

# From a list of URLs
python3 src/venom_xss.py --file targets.txt

# Save results to a custom directory and use a proxy
python3 src/venom_xss.py --url https://example.com --results-dir ./results --proxy http://127.0.0.1:8080

