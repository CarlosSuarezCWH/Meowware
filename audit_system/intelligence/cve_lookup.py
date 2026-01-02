"""
CVE Lookup Integration
Real-time CVE database queries for detected versions

Meowware v16.0 - Developed by Carlos Mancera
"""
import requests
from typing import List, Dict, Any, Optional
from ..core.http_pool import get_http_pool
from ..core.debug import debug_print

class CVELookup:
    """
    Queries CVE databases for detected software versions
    Supports multiple CVE sources for comprehensive coverage
    """
    
    def __init__(self):
        self.http_pool = get_http_pool()
        # CIRCL CVE API (free, no auth required)
        self.circl_api = "https://cve.circl.lu/api"
        # NVD API (free, rate limited)
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def lookup_cves(self, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Lookup CVEs for a specific product and version
        
        Args:
            product: Software name (e.g., "Apache", "WordPress", "PHP")
            version: Version string (e.g., "2.4.49", "6.4.2")
        
        Returns:
            List of CVE dictionaries with id, summary, cvss, etc.
        """
        cves = []
        
        # Normalize product name
        product_lower = product.lower()
        
        # Try CIRCL CVE API first (faster, no auth)
        try:
            # Search by product name
            search_url = f"{self.circl_api}/search/{product_lower}"
            response = self.http_pool.get(search_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    # Filter by version if possible
                    for cve in data:
                        if version and version in str(cve.get('summary', '')).lower():
                            cves.append({
                                'id': cve.get('id', ''),
                                'summary': cve.get('summary', ''),
                                'cvss': cve.get('cvss', 0.0),
                                'published': cve.get('Published', ''),
                                'source': 'CIRCL'
                            })
                        elif not version:  # If no version specified, include all
                            cves.append({
                                'id': cve.get('id', ''),
                                'summary': cve.get('summary', ''),
                                'cvss': cve.get('cvss', 0.0),
                                'published': cve.get('Published', ''),
                                'source': 'CIRCL'
                            })
        except Exception as e:
            debug_print(f"  ⚠️ CIRCL CVE API lookup failed: {e}")
        
        # Try NVD API (more comprehensive but slower)
        if not cves:
            try:
                # NVD requires keyword search
                search_url = f"{self.nvd_api}?keywordSearch={product} {version}"
                response = self.http_pool.get(search_url, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities[:10]:  # Limit to top 10
                        cve_item = vuln.get('cve', {})
                        cve_id = cve_item.get('id', '')
                        descriptions = cve_item.get('descriptions', [])
                        summary = descriptions[0].get('value', '') if descriptions else ''
                        
                        # Get CVSS score if available
                        metrics = cve_item.get('metrics', {})
                        cvss_v3 = metrics.get('cvssMetricV31', [])
                        cvss_score = 0.0
                        if cvss_v3:
                            cvss_score = cvss_v3[0].get('cvssData', {}).get('baseScore', 0.0)
                        
                        cves.append({
                            'id': cve_id,
                            'summary': summary,
                            'cvss': cvss_score,
                            'published': cve_item.get('published', ''),
                            'source': 'NVD'
                        })
            except Exception as e:
                debug_print(f"  ⚠️ NVD CVE API lookup failed: {e}")
        
        return cves[:20]  # Limit to 20 CVEs max
    
    def lookup_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Lookup specific CVE by ID"""
        try:
            # CIRCL API
            url = f"{self.circl_api}/cve/{cve_id}"
            response = self.http_pool.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        
        return None
    
    def enrich_finding_with_cves(self, finding_title: str, tech_versions: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Enrich finding with relevant CVEs based on detected technologies
        
        Args:
            finding_title: Title of the finding
            tech_versions: Dictionary of {technology: version}
        
        Returns:
            List of relevant CVEs
        """
        relevant_cves = []
        
        # Extract product and version from finding or tech_versions
        for product, version in tech_versions.items():
            if product.lower() in finding_title.lower():
                cves = self.lookup_cves(product, version)
                relevant_cves.extend(cves)
        
        return relevant_cves
    
    def get_cve_summary(self, product: str, version: str) -> Dict[str, Any]:
        """
        Get summary of CVEs for a product/version
        
        Returns:
            Summary with count, critical count, average CVSS, etc.
        """
        cves = self.lookup_cves(product, version)
        
        if not cves:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'average_cvss': 0.0
            }
        
        critical = sum(1 for cve in cves if cve.get('cvss', 0) >= 9.0)
        high = sum(1 for cve in cves if 7.0 <= cve.get('cvss', 0) < 9.0)
        medium = sum(1 for cve in cves if 4.0 <= cve.get('cvss', 0) < 7.0)
        low = sum(1 for cve in cves if 0 < cve.get('cvss', 0) < 4.0)
        
        avg_cvss = sum(cve.get('cvss', 0) for cve in cves) / len(cves) if cves else 0.0
        
        return {
            'total': len(cves),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'average_cvss': round(avg_cvss, 2),
            'cves': cves[:5]  # Top 5 most relevant
        }

