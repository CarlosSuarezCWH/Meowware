import subprocess
import shutil
from typing import List, Dict, Any
from .base import BaseTool
from ..core.debug import debug_print

class DNSScanner(BaseTool):
    @property
    def name(self) -> str:
        return "dnsscanner"

    def is_available(self) -> bool:
        return shutil.which("dnsrecon") is not None or shutil.which("dig") is not None

    def run(self, domain: str) -> Dict[str, Any]:
        findings = []
        ttl_results = {}
        dnssec_active = False
        debug_print(f"Scanning DNS for {domain} [Phase 4/7]...")
        
        # 1. Zone Transfer (AXFR) - v16.2: STRICT VERIFICATION REQUIRED
        # Only report AXFR if we have CONFIRMED evidence:
        # - NS server identified
        # - Complete zone transfer received (actual DNS records)
        # - Evidence of successful transfer
        axfr_confirmed = False
        axfr_ns = None
        axfr_records = []
        axfr_evidence = ""
        
        if shutil.which("dnsrecon"):
            try:
                debug_print(f"  Checking Zone Transfer (dnsrecon) - strict verification...")
                cmd = ["dnsrecon", "-d", domain, "-t", "axfr"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # v16.2: Parse output to verify REAL zone transfer
                lines = res.stdout.splitlines()
                zone_records = []
                vulnerable_ns = None
                
                for line in lines:
                    # Look for NS server that allowed transfer
                    if "NS" in line and domain in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            vulnerable_ns = parts[-1].strip()
                    
                    # Look for actual DNS records from transfer (A, AAAA, MX, CNAME, etc.)
                    if any(record_type in line for record_type in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]):
                        # Check if it's a valid DNS record line (not just a header)
                        if domain in line or any(char.isdigit() for char in line.split()[0] if line.split()):
                            zone_records.append(line.strip())
                
                # v16.2: Only report if we have CONFIRMED evidence
                if vulnerable_ns and len(zone_records) >= 3:  # At least 3 records = real transfer
                    axfr_confirmed = True
                    axfr_ns = vulnerable_ns
                    axfr_records = zone_records[:10]  # Store first 10 records as evidence
                    axfr_evidence = f"Zone transfer successful from NS: {vulnerable_ns}. Received {len(zone_records)} DNS records."
                    debug_print(f"    [✓] AXFR CONFIRMED: {vulnerable_ns} allowed zone transfer ({len(zone_records)} records)")
                else:
                    debug_print(f"    [✗] AXFR NOT CONFIRMED: No complete zone transfer detected (false positive discarded)")
                    
            except Exception as e:
                debug_print(f"    [✗] AXFR check failed: {e}")
        
        # v16.2: Also try with dig for additional verification
        if not axfr_confirmed and shutil.which("dig"):
            try:
                # Get NS servers first
                cmd_ns = ["dig", "+short", "NS", domain]
                res_ns = subprocess.run(cmd_ns, capture_output=True, text=True, timeout=10)
                ns_servers = [ns.strip() for ns in res_ns.stdout.strip().splitlines() if ns.strip()]
                
                # Try AXFR against each NS
                for ns in ns_servers[:3]:  # Limit to first 3 NS servers
                    if not ns:
                        continue
                    debug_print(f"  Attempting AXFR via dig @{ns}...")
                    cmd_axfr = ["dig", "@" + ns, "AXFR", domain]
                    res_axfr = subprocess.run(cmd_axfr, capture_output=True, text=True, timeout=15)
                    
                    # Check for actual DNS records (not just error messages)
                    output_lines = res_axfr.stdout.splitlines()
                    dns_records = [line for line in output_lines if 
                                   any(rt in line for rt in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]) and
                                   (domain in line or line.strip().startswith(domain.split('.')[0]))]
                    
                    if len(dns_records) >= 3:  # Real transfer = multiple records
                        axfr_confirmed = True
                        axfr_ns = ns
                        axfr_records = dns_records[:10]
                        axfr_evidence = f"Zone transfer confirmed via dig from NS: {ns}. Received {len(dns_records)} DNS records."
                        debug_print(f"    [✓] AXFR CONFIRMED via dig: {ns} ({len(dns_records)} records)")
                        break
                    else:
                        debug_print(f"    [✗] AXFR failed from {ns}: No complete zone transfer")
                        
            except Exception as e:
                debug_print(f"    [✗] dig AXFR check failed: {e}")
        
        # v16.2: Only add finding if CONFIRMED with evidence
        if axfr_confirmed and axfr_ns and axfr_records:
            findings.append({
                "issue": "CRITICAL: DNS Zone Transfer (AXFR)",
                "severity": "CRITICAL",
                "description": f"Domain {domain} allows full zone transfers from NS server {axfr_ns}. Complete zone transfer confirmed with {len(axfr_records)}+ DNS records received.",
                "recommendation": f"Restrict AXFR in named/bind configuration on {axfr_ns}. Configure 'allow-transfer' to only allow transfers from authorized secondary DNS servers.",
                "evidence": axfr_evidence + "\n\nSample records received:\n" + "\n".join(axfr_records[:5])
            })
        elif axfr_confirmed:
            # Partial confirmation but missing evidence - downgrade or discard
            debug_print(f"    [⚠] AXFR partially detected but evidence insufficient - DISCARDED")
        
        # 2. Recursion / Open Resolver via dig
        if shutil.which("dig"):
            try:
                debug_print(f"  Checking Open Resolver & DNSSEC (dig)...")
                # Open Resolver test
                cmd = ["dig", "@" + domain, "google.com", "A"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if "status: NOERROR" in res.stdout and "ANSWER SECTION:" in res.stdout:
                    findings.append({
                        "issue": "MEDIUM: DNS Open Resolver",
                        "severity": "MEDIUM",
                        "description": f"DNS server on {domain} allows recursive queries. Risk of DNS amplification attacks.",
                        "recommendation": "Disable recursion for external queries."
                    })
                
                # DNSSEC test
                cmd_sec = ["dig", domain, "DNSKEY", "+short"]
                res_sec = subprocess.run(cmd_sec, capture_output=True, text=True, timeout=10)
                if res_sec.stdout.strip():
                    dnssec_active = True
                    debug_print(f"    [+] DNSSEC Detected for {domain}")
                
                # 3. TTL Mapping (v14.0)
                cmd_ttl = ["dig", domain, "ANY"]
                res_ttl = subprocess.run(cmd_ttl, capture_output=True, text=True, timeout=10)
                for line in res_ttl.stdout.splitlines():
                    if "IN" in line and domain in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            record_type = parts[3]
                            ttl = parts[1]
                            if ttl.isdigit():
                                ttl_results[record_type] = int(ttl)

            except: pass
            
        if not dnssec_active:
             findings.append({
                "issue": "INFO: DNSSEC Missing",
                "severity": "INFO",
                "description": f"Domain {domain} does not have DNSSEC enabled. Risk of DNS spoofing/poisoning.",
                "recommendation": "Enable DNSSEC at your registrar."
            })

        return {
            "findings": findings,
            "ttl_map": ttl_results,
            "dnssec": dnssec_active
        }
