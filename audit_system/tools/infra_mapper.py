import requests
import json
import socket
from typing import Dict, Any
from .base import BaseTool
from ..core.debug import debug_print

class InfraMapperTool(BaseTool):
    @property
    def name(self) -> str:
        return "infra_mapper"

    def is_available(self) -> bool:
        return True

    def run(self, ip: str) -> Dict[str, Any]:
        """
        Resolves ASN, ISP, and Geolocation for a given IP.
        Uses ip-api.com (free tier) with failover.
        """
        debug_print(f"  [Infra Mapping] Resolving metadata for {ip}...")
        
        try:
            # Free API: ip-api.com (No API key required for low volume)
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        "asn": data.get('as', 'Unknown ASN'),
                        "geo": f"{data.get('city', 'Unknown City')}, {data.get('country', 'Unknown Country')}",
                        "isp": data.get('isp', 'Unknown ISP'),
                        "org": data.get('org', 'Unknown Org')
                    }
        except Exception as e:
            debug_print(f"  ⚠️ Infrastructure mapping failed for {ip}: {e}")
            
        return {
            "asn": "Unknown ASN",
            "geo": "Unknown Geo",
            "isp": "Unknown ISP",
            "org": "Unknown Org"
        }
