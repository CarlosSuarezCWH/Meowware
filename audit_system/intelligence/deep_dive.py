"""
Deep Dive Investigation System
When a vulnerability is found, this system investigates it deeply:
- Searches for CVEs
- Analyzes exploitability
- Follows attack chains
- Adapts audit flow based on findings

Meowware v16.4 - Developed by Carlos Mancera
"""
from typing import List, Dict, Any, Optional
from ..core.models import Finding, Host, Severity
from ..intelligence.cve_lookup import CVELookup
from ..core.debug import debug_print
import re

class DeepDiveInvestigator:
    """
    Investigates vulnerabilities deeply when found.
    Acts like a pentester: "I found X, now let me investigate Y and Z"
    """
    
    def __init__(self, cve_lookup: CVELookup):
        self.cve_lookup = cve_lookup
        self.investigation_queue: List[Dict[str, Any]] = []
    
    def investigate_finding(self, finding: Finding, host: Host) -> Dict[str, Any]:
        """
        Deep dive investigation of a finding.
        Returns investigation results and recommended next steps.
        """
        debug_print(f"    [Deep Dive] Investigating: {finding.title}")
        
        investigation = {
            "finding": finding,
            "cves_found": [],
            "exploitability": "unknown",
            "attack_vectors": [],
            "recommended_tools": [],
            "severity_adjusted": finding.severity,
            "investigation_notes": []
        }
        
        # 1. Extract product/version from finding
        product, version = self._extract_product_version(finding)
        
        # 2. Search for CVEs
        if product and version:
            debug_print(f"      → Searching CVEs for {product} {version}...")
            cves = self.cve_lookup.lookup_cves(product, version)
            if cves:
                investigation["cves_found"] = cves[:10]  # Top 10
                debug_print(f"      ✓ Found {len(cves)} CVEs")
                
                # Adjust severity if critical CVEs found
                critical_cves = [c for c in cves if c.get('cvss', 0) >= 9.0]
                if critical_cves and finding.severity != Severity.CRITICAL:
                    investigation["severity_adjusted"] = Severity.CRITICAL
                    investigation["investigation_notes"].append(
                        f"Severity upgraded to CRITICAL due to {len(critical_cves)} critical CVEs"
                    )
        
        # 3. Analyze exploitability
        investigation["exploitability"] = self._assess_exploitability(finding, host, investigation["cves_found"])
        
        # 4. Identify attack vectors
        investigation["attack_vectors"] = self._identify_attack_vectors(finding, host)
        
        # 5. Recommend next tools based on finding type
        investigation["recommended_tools"] = self._recommend_investigation_tools(finding, host, investigation)
        
        return investigation
    
    def _extract_product_version(self, finding: Finding) -> tuple:
        """
        Extract product and version from finding title/description
        """
        text = f"{finding.title} {finding.description}".lower()
        
        # Common patterns (expanded)
        patterns = [
            # CMS
            (r'wordpress\s+(\d+\.\d+(?:\.\d+)?)', 'WordPress'),
            (r'joomla\s+(\d+\.\d+(?:\.\d+)?)', 'Joomla'),
            (r'drupal\s+(\d+\.\d+(?:\.\d+)?)', 'Drupal'),
            (r'magento\s+(\d+\.\d+(?:\.\d+)?)', 'Magento'),
            (r'prestashop\s+(\d+\.\d+(?:\.\d+)?)', 'PrestaShop'),
            (r'moodle\s+(\d+\.\d+(?:\.\d+)?)', 'Moodle'),
            # Web Servers
            (r'apache\s+(\d+\.\d+(?:\.\d+)?)', 'Apache'),
            (r'nginx\s+(\d+\.\d+(?:\.\d+)?)', 'Nginx'),
            (r'iis\s+(\d+\.\d+(?:\.\d+)?)', 'IIS'),
            (r'tomcat\s+(\d+\.\d+(?:\.\d+)?)', 'Tomcat'),
            # Programming Languages
            (r'php\s+(\d+\.\d+(?:\.\d+)?)', 'PHP'),
            (r'python\s+(\d+\.\d+(?:\.\d+)?)', 'Python'),
            (r'node\.?js\s+(\d+\.\d+(?:\.\d+)?)', 'Node.js'),
            (r'ruby\s+(\d+\.\d+(?:\.\d+)?)', 'Ruby'),
            (r'java\s+(\d+\.\d+(?:\.\d+)?)', 'Java'),
            # Databases
            (r'mysql\s+(\d+\.\d+(?:\.\d+)?)', 'MySQL'),
            (r'postgresql\s+(\d+\.\d+(?:\.\d+)?)', 'PostgreSQL'),
            (r'mongodb\s+(\d+\.\d+(?:\.\d+)?)', 'MongoDB'),
            (r'redis\s+(\d+\.\d+(?:\.\d+)?)', 'Redis'),
            (r'elasticsearch\s+(\d+\.\d+(?:\.\d+)?)', 'Elasticsearch'),
            (r'mssql\s+(\d+\.\d+(?:\.\d+)?)', 'MSSQL'),
            # Frameworks
            (r'laravel\s+(\d+\.\d+(?:\.\d+)?)', 'Laravel'),
            (r'django\s+(\d+\.\d+(?:\.\d+)?)', 'Django'),
            (r'rails\s+(\d+\.\d+(?:\.\d+)?)', 'Ruby on Rails'),
            (r'spring\s+(\d+\.\d+(?:\.\d+)?)', 'Spring'),
            (r'express\s+(\d+\.\d+(?:\.\d+)?)', 'Express.js'),
            (r'flask\s+(\d+\.\d+(?:\.\d+)?)', 'Flask'),
            (r'symfony\s+(\d+\.\d+(?:\.\d+)?)', 'Symfony'),
            # Operating Systems
            (r'windows\s+(\d+\.\d+(?:\.\d+)?)', 'Windows'),
            (r'linux\s+(\d+\.\d+(?:\.\d+)?)', 'Linux'),
        ]
        
        for pattern, product in patterns:
            match = re.search(pattern, text)
            if match:
                return product, match.group(1)
        
        # Try to extract from CVE references
        cve_match = re.search(r'CVE-\d{4}-\d+', finding.title)
        if cve_match:
            # Try to get product from CVE description
            cve_id = cve_match.group(0)
            cve_info = self.cve_lookup.lookup_by_cve_id(cve_id)
            if cve_info:
                # Extract product from CVE summary
                summary = cve_info.get('summary', '').lower()
                for pattern, product in patterns:
                    if product.lower() in summary:
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', summary)
                        if version_match:
                            return product, version_match.group(1)
        
        return None, None
    
    def _assess_exploitability(self, finding: Finding, host: Host, cves: List[Dict[str, Any]]) -> str:
        """
        Assess how exploitable this vulnerability is
        """
        exploitability_score = 0
        
        # High severity findings are more exploitable
        if finding.severity == Severity.CRITICAL:
            exploitability_score += 3
        elif finding.severity == Severity.HIGH:
            exploitability_score += 2
        elif finding.severity == Severity.MEDIUM:
            exploitability_score += 1
        
        # CVEs with high CVSS are more exploitable
        high_cvss = [c for c in cves if c.get('cvss', 0) >= 7.0]
        exploitability_score += len(high_cvss)
        
        # Publicly exposed hosts are more exploitable
        if not host.is_internal:
            exploitability_score += 2
        
        # Web vulnerabilities on web services are more exploitable
        if finding.category in ["Web Vulnerability", "CMS", "Injection"] and host.web_context:
            exploitability_score += 2
        
        if exploitability_score >= 5:
            return "high"
        elif exploitability_score >= 3:
            return "medium"
        else:
            return "low"
    
    def _identify_attack_vectors(self, finding: Finding, host: Host) -> List[str]:
        """
        Identify potential attack vectors based on finding
        """
        vectors = []
        
        # SQL Injection
        if "sql" in finding.title.lower() or "sql" in finding.description.lower():
            vectors.append("SQL Injection → Database Access")
            if any(s.port == 3306 for s in host.services if s.state == 'open'):
                vectors.append("SQL Injection → Direct MySQL Access")
        
        # XSS
        if "xss" in finding.title.lower() or "cross-site" in finding.description.lower():
            vectors.append("XSS → Session Hijacking")
            vectors.append("XSS → Credential Theft")
        
        # RCE
        if "rce" in finding.title.lower() or "remote code execution" in finding.description.lower():
            vectors.append("RCE → Server Compromise")
            vectors.append("RCE → Lateral Movement")
        
        # File Upload
        if "upload" in finding.title.lower() or "file upload" in finding.description.lower():
            vectors.append("File Upload → Web Shell")
            vectors.append("File Upload → RCE")
        
        # Authentication Bypass
        if "auth" in finding.title.lower() or "authentication" in finding.description.lower():
            vectors.append("Auth Bypass → Unauthorized Access")
            vectors.append("Auth Bypass → Privilege Escalation")
        
        # Exposed Database
        if "database" in finding.title.lower() or "mysql" in finding.title.lower():
            vectors.append("Direct Database Access → Data Exfiltration")
            if host.web_context:
                vectors.append("Database + Web → SQL Injection Chain")
        
        return vectors
    
    def _recommend_investigation_tools(self, finding: Finding, host: Host, investigation: Dict[str, Any]) -> List[str]:
        """
        Recommend tools to investigate this finding further
        """
        tools = []
        
        finding_lower = finding.title.lower() + " " + finding.description.lower()
        
        # CMS findings
        if "wordpress" in finding_lower:
            tools.append("wpscan")  # Deep WordPress scan
            tools.append("nuclei:tags=wordpress,cve")
            if "plugin" in finding_lower or "theme" in finding_lower:
                tools.append("wpscan:enumerate=vp,vt")  # Vulnerable plugins/themes
        elif "joomla" in finding_lower:
            tools.append("joomscan")
            tools.append("nuclei:tags=joomla,cve")
        elif "drupal" in finding_lower:
            tools.append("droopescan")
            tools.append("nuclei:tags=drupal,cve")
        elif "magento" in finding_lower:
            tools.append("nuclei:tags=magento,cve")
            tools.append("nuclei:tags=ecommerce,cve")
        elif "prestashop" in finding_lower:
            tools.append("nuclei:tags=prestashop,cve")
            tools.append("nuclei:tags=ecommerce,cve")
        elif "moodle" in finding_lower:
            tools.append("nuclei:tags=moodle,cve")
        
        # SQL Injection
        if "sql" in finding_lower or "injection" in finding_lower:
            tools.append("sqlmap")
            tools.append("nuclei:tags=sql-injection")
            if any(s.port == 3306 for s in host.services if s.state == 'open'):
                tools.append("mysql-client")
        
        # XSS
        if "xss" in finding_lower or "cross-site" in finding_lower:
            tools.append("nuclei:tags=xss")
            tools.append("api-scanner")  # APIs often have XSS
        
        # RCE
        if "rce" in finding_lower or "remote code execution" in finding_lower:
            tools.append("nuclei:tags=rce")
            tools.append("feroxbuster")  # Find upload endpoints
        
        # File Upload
        if "upload" in finding_lower:
            tools.append("feroxbuster")
            tools.append("dirsearch")
            tools.append("nuclei:tags=file-upload")
        
        # Authentication issues
        if "auth" in finding_lower or "login" in finding_lower:
            tools.append("api-scanner")
            tools.append("nuclei:tags=auth-bypass")
        
        # Database exposure
        if "database" in finding_lower or "mysql" in finding_lower:
            tools.append("mysql-client")
            tools.append("nuclei:tags=mysql,exposure")
        elif "postgresql" in finding_lower or "postgres" in finding_lower:
            tools.append("nuclei:tags=postgres,exposure")
        elif "mongodb" in finding_lower or "mongo" in finding_lower:
            tools.append("nuclei:tags=mongodb,exposure")
        elif "redis" in finding_lower:
            tools.append("nuclei:tags=redis,exposure")
        elif "elasticsearch" in finding_lower:
            tools.append("nuclei:tags=elasticsearch,exposure")
        elif "mssql" in finding_lower or "sql server" in finding_lower:
            tools.append("nuclei:tags=mssql,exposure")
        
        # Framework findings
        if "laravel" in finding_lower:
            tools.append("nuclei:tags=laravel,cve")
            tools.append("api-scanner")
        elif "django" in finding_lower:
            tools.append("nuclei:tags=django,cve")
            tools.append("api-scanner")
        elif "rails" in finding_lower or "ruby on rails" in finding_lower:
            tools.append("nuclei:tags=rails,cve")
            tools.append("nuclei:tags=ruby,cve")
        elif "spring" in finding_lower:
            tools.append("nuclei:tags=spring,cve")
            tools.append("nuclei:tags=java,cve")
        elif "express" in finding_lower:
            tools.append("nuclei:tags=nodejs,cve")
            tools.append("api-scanner")
        elif "flask" in finding_lower:
            tools.append("nuclei:tags=flask,cve")
            tools.append("api-scanner")
        elif "symfony" in finding_lower:
            tools.append("nuclei:tags=symfony,cve")
        
        # Web server findings
        if "apache" in finding_lower:
            tools.append("nuclei:tags=apache,cve")
        elif "nginx" in finding_lower:
            tools.append("nuclei:tags=nginx,cve")
        elif "iis" in finding_lower:
            tools.append("nuclei:tags=iis,cve")
        elif "tomcat" in finding_lower:
            tools.append("nuclei:tags=tomcat,cve")
            tools.append("nuclei:tags=java,cve")
        
        # Programming language findings
        if "php" in finding_lower and "wordpress" not in finding_lower and "joomla" not in finding_lower:
            tools.append("nuclei:tags=php,cve")
        elif "python" in finding_lower and "django" not in finding_lower and "flask" not in finding_lower:
            tools.append("nuclei:tags=python,cve")
        elif "node" in finding_lower or "nodejs" in finding_lower:
            tools.append("nuclei:tags=nodejs,cve")
            tools.append("api-scanner")
        elif "java" in finding_lower and "spring" not in finding_lower:
            tools.append("nuclei:tags=java,cve")
        elif "ruby" in finding_lower and "rails" not in finding_lower:
            tools.append("nuclei:tags=ruby,cve")
        
        # OS findings
        if "windows" in finding_lower:
            tools.append("nuclei:tags=windows,cve")
            if "rdp" in finding_lower:
                tools.append("rdp_scanner")
            if "smb" in finding_lower:
                tools.append("smb_scanner")
        elif "linux" in finding_lower:
            tools.append("nuclei:tags=linux,cve")
            if "ssh" in finding_lower:
                tools.append("ssh_scanner")
        
        # API findings
        if "api" in finding_lower or "rest" in finding_lower or "graphql" in finding_lower:
            tools.append("api-scanner")
            tools.append("nuclei:tags=api,cve")
        
        # Container/Cloud findings
        if "docker" in finding_lower or "kubernetes" in finding_lower or "k8s" in finding_lower:
            tools.append("nuclei:tags=docker,cve")
            tools.append("nuclei:tags=kubernetes,cve")
        
        # Cloud services
        if "aws" in finding_lower or "s3" in finding_lower:
            tools.append("nuclei:tags=aws,cve")
        elif "azure" in finding_lower:
            tools.append("nuclei:tags=azure,cve")
        elif "gcp" in finding_lower or "google cloud" in finding_lower:
            tools.append("nuclei:tags=gcp,cve")
        
        # If critical CVEs found, recommend CVE-specific scans
        if investigation["cves_found"]:
            critical_cves = [c for c in investigation["cves_found"] if c.get('cvss', 0) >= 9.0]
            if critical_cves:
                tools.append("nuclei:tags=cve")
                # Add specific CVE IDs if possible
                cve_ids = [c.get('id') for c in critical_cves[:3]]
                if cve_ids:
                    tools.append(f"nuclei:cve={','.join(cve_ids)}")
        
        return list(set(tools))  # Remove duplicates

