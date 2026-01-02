"""
Threat Intelligence Integration
Checks IPs/domains against threat intelligence feeds

Meowware v16.0 - Developed by Carlos Mancera
"""
import requests
from typing import Dict, Any, Optional
from ..core.http_pool import get_http_pool
from ..core.debug import debug_print

class ThreatIntelligence:
    """
    Verifies IPs/domains against threat intelligence feeds
    Supports: VirusTotal, AbuseIPDB, URLhaus, Phishtank
    """
    
    def __init__(self, virustotal_api_key: str = None, abuseipdb_api_key: str = None):
        self.http_pool = get_http_pool()
        self.vt_api_key = virustotal_api_key
        self.abuseipdb_key = abuseipdb_api_key
    
    def check_malicious(self, target: str, target_type: str = "domain") -> Dict[str, Any]:
        """
        Check if target is in threat intelligence databases
        
        Args:
            target: IP address or domain
            target_type: "ip" or "domain"
        
        Returns:
            Threat intelligence results
        """
        results = {
            "malicious": False,
            "sources": [],
            "threat_types": [],
            "reputation_score": 100,  # 100 = clean, 0 = malicious
            "details": {}
        }
        
        # VirusTotal check
        if self.vt_api_key:
            vt_result = self._check_virustotal(target, target_type)
            if vt_result:
                results["details"]["virustotal"] = vt_result
                if vt_result.get("malicious", False):
                    results["malicious"] = True
                    results["sources"].append("VirusTotal")
                    results["threat_types"].extend(vt_result.get("threat_types", []))
                    results["reputation_score"] = min(results["reputation_score"], 
                                                     vt_result.get("reputation_score", 100))
        
        # AbuseIPDB check (IPs only)
        if target_type == "ip" and self.abuseipdb_key:
            abuse_result = self._check_abuseipdb(target)
            if abuse_result:
                results["details"]["abuseipdb"] = abuse_result
                if abuse_result.get("is_public", False) and abuse_result.get("abuse_confidence", 0) > 50:
                    results["malicious"] = True
                    results["sources"].append("AbuseIPDB")
                    results["reputation_score"] = min(results["reputation_score"], 
                                                     100 - abuse_result.get("abuse_confidence", 0))
        
        # URLhaus check (domains/URLs only)
        if target_type == "domain":
            urlhaus_result = self._check_urlhaus(target)
            if urlhaus_result:
                results["details"]["urlhaus"] = urlhaus_result
                if urlhaus_result.get("threat", False):
                    results["malicious"] = True
                    results["sources"].append("URLhaus")
                    results["threat_types"].append("Malware Distribution")
        
        return results
    
    def _check_virustotal(self, target: str, target_type: str) -> Optional[Dict[str, Any]]:
        """Check VirusTotal (requires API key)"""
        if not self.vt_api_key:
            return None
        
        try:
            if target_type == "ip":
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            else:
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            
            response = self.http_pool.get(
                url,
                params={"apikey": self.vt_api_key, target_type: target},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 1:
                    positives = data.get("positives", 0)
                    total = data.get("total", 0)
                    
                    return {
                        "malicious": positives > 0,
                        "positives": positives,
                        "total": total,
                        "reputation_score": max(0, 100 - (positives * 10)),
                        "threat_types": data.get("detected_urls", [])[:5]
                    }
        except Exception as e:
            debug_print(f"  ⚠️ VirusTotal check failed: {e}")
        
        return None
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check AbuseIPDB (requires API key)"""
        if not self.abuseipdb_key:
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            
            response = self.http_pool.get(
                url,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("data", {})
                
                return {
                    "is_public": result.get("isPublic", False),
                    "abuse_confidence": result.get("abuseConfidencePercentage", 0),
                    "usage_type": result.get("usageType", ""),
                    "isp": result.get("isp", ""),
                    "country": result.get("countryCode", "")
                }
        except Exception as e:
            debug_print(f"  ⚠️ AbuseIPDB check failed: {e}")
        
        return None
    
    def _check_urlhaus(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check URLhaus (free, no API key required)"""
        try:
            url = f"https://urlhaus-api.abuse.ch/v1/host/{domain}/"
            response = self.http_pool.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "threat": data.get("threat", False),
                        "url_count": len(data.get("urls", [])),
                        "malware_count": len(data.get("payloads", []))
                    }
        except Exception as e:
            debug_print(f"  ⚠️ URLhaus check failed: {e}")
        
        return None

