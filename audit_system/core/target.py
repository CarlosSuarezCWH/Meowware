import ipaddress
import socket
from typing import List, Optional
from .exceptions import TargetError

class Target:
    def __init__(self, input_str: str):
        self.input_str = input_str
        self.type = self._detect_type()
        self.resolved_ips: List[str] = []
        
        if self.type == 'domain':
            self.resolved_ips = self._resolve_domain()
        else:
            self.resolved_ips = [self.input_str]

    def _detect_type(self) -> str:
        try:
            ipaddress.ip_address(self.input_str)
            return 'ip'
        except ValueError:
            # Simple domain validation
            if '.' in self.input_str and not self.input_str.startswith('-'):
                return 'domain'
            raise TargetError(f"Invalid target format: {self.input_str}")

    def _resolve_domain(self) -> List[str]:
        try:
            # Get all associated IPs
            addr_info = socket.getaddrinfo(self.input_str, None)
            ips = list(set([info[4][0] for info in addr_info]))
            
            # Sort IPs: IPv4 first (length usually shorter), then IPv6
            # A simple heuristic: IPv4 contains '.', IPv6 contains ':'
            ips.sort(key=lambda ip: 0 if '.' in ip else 1)
            
            return ips
        except socket.gaierror as e:
            raise TargetError(f"Could not resolve domain {self.input_str}: {e}")

    def to_dict(self) -> dict:
        return {
            "input": self.input_str,
            "type": self.type,
            "resolved_ips": self.resolved_ips
        }
