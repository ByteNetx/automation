import ipaddress
import dns.resolver
import dns.reversename
from typing import List

class DNSTool:
    """A comprehensive DNS tool using dnspython library"""
    
    def __init__(self, dns_server: str = None):
        """
        Initialize DNS resolver
        :param dns_server: Custom DNS server (e.g., '8.8.8.8' for Google DNS)
        """
        self.resolver = dns.resolver.Resolver()
        if dns_server:
            self.resolver.nameservers = [dns_server]

    def query_record(self, domain: str, record_type: str) -> List[str]:
        """
        Generic DNS record query
        :param domain: Target domain (e.g., 'google.com')
        :param record_type: DNS record type (A, MX, NS, CNAME, TXT, SOA)
        :return: List of record values
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(ans) for ans in answers]
        except dns.resolver.NXDOMAIN:
            return [f"❌ Domain {domain} does not exist"]
        except dns.resolver.NoAnswer:
            return [f"ℹ️ No {record_type} records found for {domain}"]
        except dns.resolver.Timeout:
            return ["❌ DNS query timed out"]
        except Exception as e:
            return [f"❌ Error: {str(e)}"]

    def get_a_records(self, domain: str) -> List[str]:
        """Get IPv4 (A) records"""
        return self.query_record(domain, "A")

    def get_mx_records(self, domain: str) -> List[str]:
        """Get Mail Exchange (MX) records"""
        return self.query_record(domain, "MX")

    def get_ns_records(self, domain: str) -> List[str]:
        """Get Name Server (NS) records"""
        return self.query_record(domain, "NS")

    def get_cname_records(self, domain: str) -> List[str]:
        """Get Canonical Name (CNAME) records"""
        return self.query_record(domain, "CNAME")

    def get_txt_records(self, domain: str) -> List[str]:
        """Get Text (TXT) records"""
        return self.query_record(domain, "TXT")

    def get_soa_records(self, domain: str) -> List[str]:
        """Get Start of Authority (SOA) records"""
        return self.query_record(domain, "SOA")

    def reverse_dns_lookup(self, ip_address: str) -> List[str]:
        """
        Reverse DNS lookup (IP → Domain)
        :param ip_address: IPv4 address (e.g., '8.8.8.8')
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [str(ans) for ans in answers]
        except Exception as e:
            return [f"❌ Reverse lookup failed: {str(e)}"]

    def full_dns_scan(self, domain: str):
        """Run a full DNS scan for all common record types"""
        print(f"\n{'='*50}")
        print(f"FULL DNS SCAN: {domain}")
        print(f"DNS Server: {self.resolver.nameservers[0] if self.resolver.nameservers else 'Default'}")
        print('='*50)

        scans = {
            "A (IPv4)": self.get_a_records,
            "MX (Mail)": self.get_mx_records,
            "NS (Name Servers)": self.get_ns_records,
            "CNAME": self.get_cname_records,
            "TXT": self.get_txt_records,
            "SOA": self.get_soa_records
        }

        for record_name, func in scans.items():
            print(f"\n📌 {record_name}:")
            for result in func(domain):
                print(f"   {result}")

def validate_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

# ------------------------------
# Interactive CLI for the DNS Tool
# ------------------------------
if __name__ == "__main__":
    print("🚀 DNS Tool using dnspython")
    print("---------------------------")
    
    # Get custom DNS server (optional)
    custom_dns = input("Enter custom DNS server (press Enter for default): ").strip()
    dns_tool = DNSTool(dns_server=custom_dns if custom_dns else None)

    # Get target domain/IP
    target = input("Enter domain or IP (e.g., google.com, 8.8.8.8): ").strip()
    
    if not target:
        print("❌ Please enter a valid domain/IP!")
        exit(1)

    # Check if input is an IP (for reverse DNS)
    if validate_ip(target):
        print("\n🔍 Performing Reverse DNS Lookup...")
        results = dns_tool.reverse_dns_lookup(target)
        for res in results:
            print(res)
    else:
        # Full DNS scan for domains
        dns_tool.full_dns_scan(target)
