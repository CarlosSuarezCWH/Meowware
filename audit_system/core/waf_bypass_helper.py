"""
WAF Bypass Helper
Helper to integrate WAF bypass into HTTP requests

Meowware v17.0 - Developed by Carlos Mancera
"""
import requests
from typing import Dict, Any, Optional
from ..evasion.waf_bypass import WAFBypass

class WAFBypassHelper:
    """
    Helper to apply WAF bypass techniques to HTTP requests.
    """
    
    def __init__(self):
        self.waf_bypass = WAFBypass()
    
    def get(self, url: str, waf_detected: bool = False, payload: str = None, **kwargs) -> requests.Response:
        """
        Make GET request with WAF bypass if needed.
        """
        if waf_detected and payload:
            # Generate bypass request
            bypass_request = self.waf_bypass.generate_bypass_request(url, payload, method="GET")
            # Update headers
            headers = kwargs.get('headers', {})
            headers.update(bypass_request.get('headers', {}))
            kwargs['headers'] = headers
            # Use bypass payload if applicable
            if 'params' in kwargs and isinstance(kwargs['params'], dict):
                # Apply bypass to parameters
                for key, value in kwargs['params'].items():
                    if isinstance(value, str):
                        bypass_payloads = self.waf_bypass.bypass_waf(value)
                        if bypass_payloads:
                            kwargs['params'][key] = bypass_payloads[0]['payload']
        
        return requests.get(url, **kwargs)
    
    def post(self, url: str, waf_detected: bool = False, payload: str = None, **kwargs) -> requests.Response:
        """
        Make POST request with WAF bypass if needed.
        """
        if waf_detected and payload:
            # Generate bypass request
            bypass_request = self.waf_bypass.generate_bypass_request(url, payload, method="POST")
            # Update headers
            headers = kwargs.get('headers', {})
            headers.update(bypass_request.get('headers', {}))
            kwargs['headers'] = headers
        
        return requests.post(url, **kwargs)


