import subprocess
import shutil
import requests
import json
import socket
import uuid
from typing import List
from .base import BaseTool
from ..core.debug import debug_print

class SubdomainTool(BaseTool):
    @property
    def name(self) -> str:
        return "subdomain_discovery"

    def _is_wildcard_dns(self, domain: str) -> bool:
        """
        Check if domain has wildcard DNS (*.domain.com resolves to same IP).
        Returns True if wildcard detected.
        """
        try:
            # Test with random subdomain
            random_sub = f"{uuid.uuid4().hex[:8]}.{domain}"
            socket.gethostbyname(random_sub)
            debug_print(f"  ⚠️  Wildcard DNS detected for {domain}")
            return True
        except socket.gaierror:
            # Random subdomain doesn't resolve = no wildcard
            return False

    def _filter_valid_subdomains(self, subdomains: List[str], domain: str) -> tuple[List[str], List[str]]:
        """
        Filter out subdomains that don't actually resolve.
        Returns (valid, failed) lists.
        v17.3: Agrupa mensajes de skipping para reducir verbosidad
        """
        valid = []
        failed = []
        skipped_count = 0
        for sub in subdomains:
            try:
                socket.gethostbyname(sub)
                valid.append(sub)
            except socket.gaierror:
                failed.append(sub)
                skipped_count += 1
                # v17.3: Solo mostrar primeros 5, luego resumir
                if skipped_count <= 5:
                    debug_print(f"  Skipping {sub} (doesn't resolve)")
        
        # v17.3: Mostrar resumen si hay muchos skipped
        if skipped_count > 5:
            debug_print(f"  ... and {skipped_count - 5} more subdomains skipped (don't resolve)")
        
        return valid, failed

    def is_available(self) -> bool:
        """Always available via crt.sh API fallback."""
        return True
    def _call_crtsh_api(self, domain: str) -> List[str]:
        """
        Queries crt.sh for historical certificates (Certificate Transparency Logs).
        v14.0: Improved parsing and deduplication.
        """
        debug_print(f"  Querying crt.sh (CT Logs) for {domain}...")
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                subs = set()
                for entry in data:
                    name = entry.get('common_name', '')
                    if name: subs.add(name.lower())
                    alt_names = entry.get('name_value', '').split('\n')
                    for an in alt_names:
                        if an: subs.add(an.strip().lower())
                return [s for s in subs if s.endswith(domain) and '*' not in s]
        except Exception as e:
            debug_print(f"  crt.sh failed: {e}")
        return []

    def discover_related_domains(self, domain: str) -> List[str]:
        """
        v14.0: Discovery of related root domains.
        """
        debug_print(f"  [Advanced Recon] Searching for related domains to {domain}...")
        return []

    def run(self, domain: str) -> List[str]:
        """
        Discovers subdomains using multiple methods with v12.1 Resilience.
        """
        subdomains = {domain}
        debug_print(f"Subdomain discovery for {domain}...")
        
        if self._is_wildcard_dns(domain):
            debug_print(f"  Wildcard DNS active - subdomain discovery may be unreliable")

        # Try assetfinder
        if shutil.which("assetfinder"):
            try:
                cmd = ["assetfinder", "--subs-only", domain]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                for line in res.stdout.splitlines():
                    clean = line.strip()
                    if clean and clean.endswith(domain): subdomains.add(clean)
            except: pass
        
        # Try amass (passive - quick mode)
        if shutil.which("amass"):
            try:
                debug_print(f"  [Discovery] Running amass (passive)...")
                cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                for line in res.stdout.splitlines():
                    clean = line.strip()
                    if clean and domain in clean: subdomains.add(clean)
            except: pass

        # Try subfinder
        if shutil.which("subfinder"):
            try:
                cmd = ["subfinder", "-d", domain, "-silent"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                for line in res.stdout.splitlines():
                    clean = line.strip()
                    if clean: subdomains.add(clean)
            except: pass

        # v12.5: Phase 5 - Proactive Origin Hunting (Guessing sensitive subdomains)
        origin_hints = ["mail", "smtp", "dev", "stage", "admin", "vpn", "mfa", "remote", "direct", "origin", "backend"]
        for hint in origin_hints:
            subdomains.add(f"{hint}.{domain}")

        # Fallback: crt.sh with retries
        crtsh_subs = self._call_crtsh_api(domain)
        for s in crtsh_subs: subdomains.add(s)

        # Filter out non-resolving subdomains
        debug_print(f"  Validating {len(subdomains)} discovered subdomains...")
        valid_subdomains, failed_subdomains = self._filter_valid_subdomains(list(subdomains), domain)
        
        result = {
            "active": sorted(valid_subdomains),
            "failed": sorted(failed_subdomains)
        }
        debug_print(f"Total valid subdomains: {len(result['active'])} | Failed: {len(result['failed'])}")
        return result


