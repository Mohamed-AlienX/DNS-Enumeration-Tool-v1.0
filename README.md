# DNS-Enumeration-Tool-v1.0

A Python-based tool designed for **DNS information gathering and analysis**, focusing on DNS records, zone transfer testing, reverse DNS lookups, and WHOIS data collection.

This project is built for **security testing, blue team analysis, and infrastructure assessment**, without performing any subdomain discovery.

---

## 🎯 Purpose

Organisations often unintentionally expose sensitive DNS information.  
This tool helps identify:

- Misconfigured DNS records  
- Open zone transfer vulnerabilities  
- Infrastructure details leaked via DNS and WHOIS  

It is intended for **authorised security testing and educational use only**.

---

## ✨ Features

### 🔹 DNS Record Analysis
- Supports: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, `SRV`, `PTR`, `DNSKEY`, `DS`
- Custom record type selection via CLI

### 🔹 Advanced DNS Techniques
- Zone Transfer (AXFR) testing
- Reverse DNS lookups
- WHOIS information gathering

### 🔹 Performance & Usability
- Multi-threaded execution
- Configurable timeout and thread count
- Optional output file saving
- Clean and readable CLI interface

### 🔹 Stability & Error Handling
- Graceful handling of timeouts
- Detailed error reporting
- Safe interruption handling (`Ctrl + C`)

---

## 🚫 Out of Scope

This tool **does NOT perform**:

- Subdomain discovery
- Subdomain brute forcing
- Wordlist-based enumeration

The focus is strictly on **DNS record-level intelligence and analysis**.

---

## 📦 Installation

```bash
pip install dnspython
pip install python-whois

Or install all dependencies at once:

pip install -r requirements.txt
```

##🚀 Usage Examples
```bash
# Basic enumeration
python dns_enum.py -d example.com

# Save results to a file
python dns_enum.py -d example.com -o results.txt

# Custom record types and threads
python dns_enum.py -d example.com -t 20 --record-types A,MX,NS,TXT
```
## 🧠 How It Works (Brief)

1. Collects DNS records using dnspython

2. Tests name servers for zone transfer misconfiguration

3. Extracts ownership and registration data via WHOIS

4. Performs reverse DNS lookups on discovered IPs

5. Summarises findings in a clean and structured output format

## ⚠️ Disclaimer

This project is for educational purposes and authorised security testing only.
Please don't scan or test domains without explicit permission from the owner.
