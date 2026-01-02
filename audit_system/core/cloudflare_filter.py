"""
Cloudflare IP Range Filter
v16.2: Filters Cloudflare IPs to avoid wasting time on edge nodes
"""
import ipaddress
from typing import List, Set

class CloudflareFilter:
    """Detects and filters Cloudflare IP addresses"""
    
    # Cloudflare IPv4 ranges
    CLOUDFLARE_IPV4_RANGES = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    ]
    
    # Cloudflare IPv6 ranges
    CLOUDFLARE_IPV6_RANGES = [
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32"
    ]
    
    def __init__(self):
        """Pre-compile Cloudflare networks for fast lookup"""
        self.ipv4_networks: List[ipaddress.IPv4Network] = [
            ipaddress.IPv4Network(range_str) for range_str in self.CLOUDFLARE_IPV4_RANGES
        ]
        self.ipv6_networks: List[ipaddress.IPv6Network] = [
            ipaddress.IPv6Network(range_str) for range_str in self.CLOUDFLARE_IPV6_RANGES
        ]
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """
        Check if an IP address belongs to Cloudflare
        
        Args:
            ip: IP address string (IPv4 or IPv6)
        
        Returns:
            True if IP is in Cloudflare ranges, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if isinstance(ip_obj, ipaddress.IPv4Address):
                for network in self.ipv4_networks:
                    if ip_obj in network:
                        return True
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                for network in self.ipv6_networks:
                    if ip_obj in network:
                        return True
        except ValueError:
            # Invalid IP format
            return False
        
        return False
    
    def filter_cloudflare_hosts(self, hosts: List) -> tuple:
        """
        Filter out Cloudflare hosts from a list
        
        Args:
            hosts: List of Host objects or IP strings
        
        Returns:
            Tuple of (filtered_hosts, cloudflare_hosts)
        """
        filtered = []
        cloudflare = []
        
        for host in hosts:
            # Extract IP from host object or use directly
            if hasattr(host, 'ip'):
                ip = host.ip
            elif isinstance(host, str):
                ip = host
            else:
                continue
            
            if self.is_cloudflare_ip(ip):
                cloudflare.append(host)
            else:
                filtered.append(host)
        
        return filtered, cloudflare



