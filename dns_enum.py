import dns.resolver
import dns.reversename
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys

class DNSEnumerator:
    def __init__(self, domain, threads=10, timeout=5):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.results = {}
    
    def query_record_type(self, record_type):
        """Query specific DNS record type"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            answers = resolver.resolve(self.domain, record_type)
            records = [str(rdata) for rdata in answers]
            return (record_type, records)
        except dns.resolver.NoAnswer:
            return (record_type, [])
        except dns.resolver.NXDOMAIN:
            return (record_type, ["❌ Domain does not exist"])
        except dns.resolver.Timeout:
            return (record_type, ["⏰ Timeout"])
        except dns.resolver.NoNameservers:
            return (record_type, ["❌ No nameservers"])
        except Exception as e:
            return (record_type, [f"❌ Error: {str(e)}"])
    
    def enumerate_records(self, custom_types=None):
        """Enumerate all DNS record types"""
        print(f"[*] Collecting DNS information for {self.domain}")
        
        # Default record types or use custom ones
        if custom_types:
            record_types = custom_types
        else:
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'SRV', 'PTR', 'DNSKEY', 'DS']
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.query_record_type, rt): rt for rt in record_types}
            
            for future in as_completed(futures):
                record_type, records = future.result()
                self.results[record_type] = records
                
                if records and not any(x in str(records[0]) for x in ["❌", "⏰"]):
                    print(f"[+] {record_type} records:")
                    for record in records:
                        print(f"    ├─ {record}")
                    print()  # Empty line for readability
    
    def reverse_lookup(self, ips=None):
        """Perform reverse DNS lookup"""
        print("[*] Performing reverse DNS lookups")
        
        # If no IPs provided, use A records from results
        if not ips and 'A' in self.results:
            ips = self.results['A']
        elif ips:
            pass  # Use provided IPs
        else:
            print("[-] No IPs available for reverse lookup")
            return []
        
        reverse_results = []
        for ip in ips:
            try:
                # Skip if it's not an IP (could be error message)
                if not any(char.isdigit() for char in ip):
                    continue
                    
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"[+] {ip} → {hostname}")
                reverse_results.append((ip, hostname))
            except (socket.herror, socket.gaierror):
                continue
            except Exception as e:
                print(f"[-] Error looking up {ip}: {e}")
        
        return reverse_results
    
    def get_whois_info(self):
        """Get basic WHOIS information"""
        try:
            import whois
            print("[*] Fetching WHOIS information...")
            domain_info = whois.whois(self.domain)
            
            print("[+] WHOIS Information:")
            if domain_info.domain_name:
                print(f"    Domain: {domain_info.domain_name}")
            if domain_info.registrar:
                print(f"    Registrar: {domain_info.registrar}")
            if domain_info.creation_date:
                print(f"    Creation Date: {domain_info.creation_date}")
            if domain_info.expiration_date:
                print(f"    Expiration Date: {domain_info.expiration_date}")
            if domain_info.name_servers:
                print(f"    Name Servers: {', '.join(domain_info.name_servers[:5])}")
            if domain_info.emails:
                print(f"    Contact Emails: {', '.join(domain_info.emails[:3])}")
                
            return domain_info
        except ImportError:
            print("[-] WHOIS library not installed. Install: pip install python-whois")
        except Exception as e:
            print(f"[-] WHOIS error: {e}")
        return None
    
    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        print("[*] Attempting zone transfer (AXFR)")
        
        try:
            # Get nameservers
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            ns_records = resolver.resolve(self.domain, 'NS')
            
            zone_transfer_success = False
            
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                print(f"[*] Testing zone transfer on {ns_server}")
                
                try:
                    # Try AXFR
                    transfer = dns.query.xfr(ns_server, self.domain, lifetime=10)
                    zone = dns.zone.from_xfr(transfer)
                    
                    print(f"[!] ⚠️  Zone transfer SUCCESSFUL on {ns_server}")
                    print(f"[!] Found {len(zone.nodes)} records")
                    
                    # Show first 10 records as example
                    count = 0
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                print(f"    {name}.{self.domain}. IN {rdataset.rdtype} {rdata}")
                                count += 1
                                if count >= 10:  # Limit output
                                    print("    ... (truncated)")
                                    break
                            if count >= 10:
                                break
                        if count >= 10:
                            break
                    
                    zone_transfer_success = True
                    break  # Stop after first success
                    
                except Exception as e:
                    print(f"[-] Zone transfer failed on {ns_server}: {str(e).split(':')[0]}")
        
        except Exception as e:
            print(f"[-] Zone transfer error: {e}")
        
        if not zone_transfer_success:
            print("[-] No zone transfers successful")
        
        return zone_transfer_success
    
    def run_full_enumeration(self):
        """Run complete DNS enumeration"""
        print(f"\n{'='*60}")
        print(f"DNS ENUMERATION FOR: {self.domain}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # 1. Enumerate basic DNS records
        print("[*] PHASE 1: Basic DNS Record Enumeration")
        self.enumerate_records()
        print()
        
        # 2. Zone transfer attempt
        print("[*] PHASE 2: Zone Transfer Test")
        self.zone_transfer()
        print()
        
        # 3. WHOIS information
        print("[*] PHASE 3: WHOIS Lookup")
        self.get_whois_info()
        print()
        
        # 4. Reverse DNS
        print("[*] PHASE 4: Reverse DNS Lookup")
        self.reverse_lookup()
        print()
        
        # Show summary
        self.show_summary(start_time)
    
    def show_summary(self, start_time):
        """Show summary of findings"""
        print(f"\n{'='*60}")
        print("ENUMERATION SUMMARY")
        print(f"{'='*60}")
        
        # Count total records found
        total_records = 0
        for record_type, records in self.results.items():
            if records and not any(x in str(records[0]) for x in ["❌", "⏰"]):
                total_records += len(records)
                print(f"✓ {record_type}: {len(records)} records")
        
        # Calculate time
        elapsed = time.time() - start_time
        print(f"\n✓ Total execution time: {elapsed:.2f} seconds")
        print(f"✓ Target: {self.domain}")
        print(f"✓ Records found: {total_records}")
        print(f"{'='*60}")

def display_banner():
    """Display tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                 DNS ENUMERATION TOOL                     ║
║          Basic DNS Information Gathering                 ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description='Basic DNS Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com -t 20 -o results.txt
  %(prog)s -d example.com --record-types A,MX,NS
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--record-types', help='Comma-separated DNS record types to check')
    parser.add_argument('--timeout', type=int, default=5, 
                       help='Timeout for DNS queries in seconds (default: 5)')
    parser.add_argument('--no-banner', action='store_true', 
                       help='Don\'t display banner')
    parser.add_argument('--quiet', action='store_true', 
                       help='Quiet mode, minimal output')
    
    args = parser.parse_args()
    
    # Display banner
    if not args.no_banner:
        display_banner()
    
    # Create enumerator object
    enumerator = DNSEnumerator(args.domain, args.threads, args.timeout)
    
    # Parse custom record types if provided
    custom_types = None
    if args.record_types:
        custom_types = [rt.strip().upper() for rt in args.record_types.split(',')]
        print(f"[*] Using custom record types: {', '.join(custom_types)}")
    
    try:
        print(f"[*] Starting DNS enumeration on {args.domain}")
        enumerator.run_full_enumeration()
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"DNS Enumeration Results for: {args.domain}\n")
                f.write("="*60 + "\n\n")
                
                # Write DNS records
                f.write("DNS RECORDS:\n")
                f.write("-"*40 + "\n")
                for record_type, records in enumerator.results.items():
                    if records and not any(x in str(records[0]) for x in ["❌", "⏰"]):
                        f.write(f"{record_type}:\n")
                        for record in records:
                            f.write(f"  {record}\n")
                        f.write("\n")
                
                # Write timestamp
                from datetime import datetime
                f.write(f"\n\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print(f"[+] Results saved to: {args.output}")
    
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
