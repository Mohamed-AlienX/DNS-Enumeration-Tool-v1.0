# DNS-Enumeration-Tool-v1.0


A Python-based tool designed for DNS information gathering and analysis, focusing on DNS records, zone transfer testing, reverse DNS lookups, and WHOIS data collection.

This project is built for security testing, blue team analysis, and infrastructure assessment, without performing any subdomain discovery.

#🎯 Purpose

Organizations often expose sensitive DNS information unintentionally.
This tool helps identify:

Misconfigured DNS records

Open zone transfer vulnerabilities

Infrastructure details leaked via DNS and WHOIS

It is intended for authorized security testing and educational use only.

✨ Features
🔹 DNS Record Analysis

Supports: A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, PTR, DNSKEY, DS

Custom record type selection via CLI

🔹 Advanced DNS Techniques

Zone Transfer (AXFR) testing

Reverse DNS lookups

WHOIS information gathering

🔹 Performance & Usability

Multi-threaded execution

Configurable timeout and threads

Optional output file saving

Clean CLI interface

🔹 Stability & Error Handling

Graceful handling of timeouts

Detailed error reporting

Safe interruption handling (Ctrl+C)

🚫 Out of Scope

This tool does NOT perform:

Subdomain discovery

Subdomain brute forcing

Wordlist-based enumeration

The focus is strictly on DNS record-level intelligence and analysis.

📦 Installation
pip install dnspython
pip install python-whois


Or:

pip install -r requirements.txt

🚀 Usage Examples
# Basic enumeration
python dns_enum.py -d example.com

# Save results to a file
python dns_enum.py -d example.com -o results.txt

# Custom record types and threads
python dns_enum.py -d example.com -t 20 --record-types A,MX,NS,TXT

🧠 How It Works (Brief)

Collects DNS records using dnspython

Tests name servers for zone transfer misconfiguration

Extracts ownership and registration data via WHOIS

Performs reverse DNS on discovered IPs

Summarises findings in a clean output format

⚠️ Disclaimer

This project is for educational and authorized security testing only.
Do not scan domains without explicit permission.

📌 Skills Demonstrated

Python scripting

DNS protocol understanding

Security misconfiguration detection

CLI tool design

Multithreading

Error handling
