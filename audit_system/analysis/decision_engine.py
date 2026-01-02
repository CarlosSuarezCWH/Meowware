from typing import List, Optional, Dict, Any
from ..core.models import Host, DNSInfo, Finding, Severity, Service, WebContext

class IntelligentDecisionEngine:
    """
    AI-Driven Decision Engine
    Decides which tools to run based on context, not blind scanning
    """
    
    @staticmethod
    def decide_tools(host: Host, dns_info: Optional[DNSInfo] = None) -> Dict[str, Any]:
        """
        Intelligent tool selection based on:
        - Application type
        - Detected services
        - Visible technologies
        - Potential risk
        - Host context
        
        Returns: {
            "cms_scan": {"tool": "wpscan", "reason": "...", "priority": "high"},
            "vuln_scan": {"tool": "nikto", "reason": "...", "priority": "medium"},
            ...
        }
        """
        decisions = {}
        reasoning = []
        
        # 1. CMS DETECTION & SPECIALIZED SCANNING
        if host.web_context:
            cms = host.web_context.cms_detected.lower() if host.web_context.cms_detected else ""
            tech_stack = [t.lower() for t in host.web_context.tech_stack]
            tech_versions = host.web_context.tech_versions if hasattr(host.web_context, 'tech_versions') else {}
            
            # WordPress Detection
            if "wordpress" in cms or any("wordpress" in t for t in tech_stack):
                # v16.2: WordPress confirmed - use aggressive mode to enumerate plugins/themes/users
                has_waf = host.web_context.waf_detected if host.web_context else False
                decisions["cms_scan"] = {
                    "tool": "wpscan",
                    "reason": "WordPress CMS confirmed - enumerating plugins, themes, and users for vulnerabilities",
                    "priority": "high",
                    "aggressive": True  # v16.2: Always enumerate when WordPress confirmed
                }
                reasoning.append("WordPress confirmed: WPScan will enumerate plugins, themes, and users")
                if has_waf:
                    reasoning.append("WAF detected - enumeration may be limited but will be attempted")
                
                # Add version-specific checks if version detected
                if host.web_context.cms_version:
                    reasoning.append(f"WordPress version {host.web_context.cms_version} detected - checking for version-specific CVEs")
            
            # v16.2: API Detection
            if host.web_context and host.web_context.url:
                url = host.web_context.url.lower()
                if any(api_marker in url for api_marker in ['/api', '/rest', '/graphql', '/v1', '/v2']):
                    decisions["api_scan"] = {
                        "tool": "api-scanner",
                        "reason": "API endpoints detected - scanning for API-specific vulnerabilities",
                        "priority": "high"
                    }
                    reasoning.append("API endpoints detected: API scanner will test for authentication, CORS, and GraphQL issues")
            
            # Joomla Detection
            elif "joomla" in cms or any("joomla" in t for t in tech_stack):
                decisions["cms_scan"] = {
                    "tool": "joomscan",
                    "reason": "Joomla CMS detected - checking for component vulnerabilities",
                    "priority": "high"
                }
                decisions["cms_scan_alt"] = {
                    "tool": "droopescan",
                    "cms_type": "joomla",
                    "reason": "Additional Joomla fingerprinting",
                    "priority": "medium"
                }
                reasoning.append("Joomla identified: Joomscan + Droopescan for comprehensive analysis")
            
            # Drupal Detection
            elif "drupal" in cms or any("drupal" in t for t in tech_stack):
                decisions["cms_scan"] = {
                    "tool": "droopescan",
                    "cms_type": "drupal",
                    "reason": "Drupal CMS detected - checking for module vulnerabilities",
                    "priority": "high"
                }
                reasoning.append("Drupal identified: Droopescan for module analysis")
            
            # Magento Detection
            elif "magento" in cms or any("magento" in t for t in tech_stack):
                decisions["cms_scan"] = {
                    "tool": "droopescan",
                    "cms_type": "magento",
                    "reason": "Magento e-commerce detected - checking for module vulnerabilities",
                    "priority": "high"
                }
                decisions["web_vuln_scan"] = {
                    "tool": "nikto",
                    "reason": "Magento detected - comprehensive web vulnerability scan",
                    "priority": "medium"
                }
                reasoning.append("Magento identified: Droopescan + Nikto for e-commerce security audit")
            
            # PrestaShop Detection
            elif "prestashop" in cms or any("prestashop" in t for t in tech_stack):
                decisions["web_vuln_scan"] = {
                    "tool": "nikto",
                    "reason": "PrestaShop e-commerce detected - comprehensive vulnerability scan",
                    "priority": "high"
                }
                reasoning.append("PrestaShop identified: Nikto for e-commerce security audit")
            
            # Moodle Detection
            elif "moodle" in cms or any("moodle" in t for t in tech_stack):
                decisions["web_vuln_scan"] = {
                    "tool": "nikto",
                    "reason": "Moodle LMS detected - comprehensive vulnerability scan",
                    "priority": "high"
                }
                reasoning.append("Moodle identified: Nikto for LMS security audit")
            
            # General Web Application (NO CMS detected)
            else:
                # v16.3: More intrusive - use multiple tools for non-CMS web apps
                decisions["web_vuln_scan"] = {
                    "tool": "nikto",
                    "reason": "Generic web application - comprehensive vulnerability scanning",
                    "priority": "high"
                }
                decisions["directory_scan"] = {
                    "tool": "dirsearch",
                    "reason": "Non-CMS web app - directory enumeration for hidden paths",
                    "priority": "high"
                }
                decisions["web_fuzzing"] = {
                    "tool": "feroxbuster",
                    "reason": "Non-CMS web app - aggressive web fuzzing for discovery",
                    "priority": "medium",
                    "aggressive": True
                }
                reasoning.append("Generic web app (no CMS): Nikto + Dirsearch + Feroxbuster for comprehensive coverage")
            
            # Web Server Version Detection & Specific Tools
            web_server = None
            web_server_version = None
            for tech_name, tech_version in tech_versions.items():
                tech_lower = tech_name.lower()
                if any(server in tech_lower for server in ["apache", "nginx", "iis", "tomcat", "jetty"]):
                    web_server = tech_name
                    web_server_version = tech_version
                    break
            
            if web_server and web_server_version:
                reasoning.append(f"Web server detected: {web_server} {web_server_version} - checking for version-specific vulnerabilities")
                decisions["server_vuln_scan"] = {
                    "tool": "nuclei",
                    "reason": f"{web_server} {web_server_version} detected - running server-specific vulnerability templates",
                    "priority": "high",
                    "tags": f"{web_server.lower()},cve"
                }
            
            # PHP Version Detection
            if any("php" in t.lower() for t in tech_stack):
                php_version = tech_versions.get("PHP", "")
                if php_version:
                    reasoning.append(f"PHP {php_version} detected - checking for PHP-specific vulnerabilities")
                    decisions["php_vuln_scan"] = {
                        "tool": "nuclei",
                        "reason": f"PHP {php_version} detected - PHP vulnerability templates",
                        "priority": "medium",
                        "tags": "php,cve"
                    }
            
            # Framework Detection (Laravel, Symfony, Django, etc.)
            if any("laravel" in t.lower() for t in tech_stack):
                decisions["framework_scan"] = {
                    "tool": "nuclei",
                    "reason": "Laravel framework detected - framework-specific vulnerability scan",
                    "priority": "medium",
                    "tags": "laravel"
                }
                reasoning.append("Laravel framework: Nuclei Laravel templates")
            
            if any("django" in t.lower() for t in tech_stack):
                decisions["framework_scan"] = {
                    "tool": "nuclei",
                    "reason": "Django framework detected - framework-specific vulnerability scan",
                    "priority": "medium",
                    "tags": "django"
                }
                reasoning.append("Django framework: Nuclei Django templates")
            
            if any("symfony" in t.lower() for t in tech_stack):
                decisions["framework_scan"] = {
                    "tool": "nuclei",
                    "reason": "Symfony framework detected - framework-specific vulnerability scan",
                    "priority": "medium",
                    "tags": "symfony"
                }
                reasoning.append("Symfony framework: Nuclei Symfony templates")
        
        # 2. SSL/TLS ANALYSIS
        https_services = [s for s in host.services if s.port in [443, 8443] and s.state == 'open']
        if https_services:
            decisions["tls_scan"] = {
                "tool": "testssl",
                "reason": "HTTPS detected - analyzing SSL/TLS configuration for weak ciphers and vulnerabilities",
                "priority": "high"
            }
            decisions["ssl_scan"] = {
                "tool": "sslscan",
                "reason": "HTTPS detected - additional SSL/TLS cipher suite analysis",
                "priority": "medium"
            }
            reasoning.append("HTTPS service: TestSSL + SSLScan for comprehensive TLS security posture")
        
        # 3. DATABASE EXPOSURE RISK
        db_services = [s for s in host.services if s.port in [3306, 5432, 27017, 1433] and s.state == 'open']
        if db_services:
            web_services = [s for s in host.services if s.port in [80, 443, 8080, 8443] and s.state == 'open']
            
            if web_services and db_services:
                decisions["sql_injection_test"] = {
                    "tool": "sqlmap",
                    "reason": "MySQL exposed on host with web services - indicates poor segmentation and potential SQL injection risk",
                    "priority": "high",  # v17.6: Not "critical" - it's a risk, not confirmed vulnerability
                    "aggressive": False  # Detection only
                }
                # v16.2: Only if MySQL port 3306 is CONFIRMED open (not inferred)
                mysql_confirmed = any(s.port == 3306 and s.state == 'open' for s in host.services)
                if mysql_confirmed:
                    # v17.6: Architectural risk, not confirmed SQLi
                    reasoning.append("Architectural Risk: Database + Web on same host = Poor segmentation (increases impact of potential SQLi, but does not confirm it)")
                else:
                    # Remove this decision if MySQL not confirmed
                    if "sql_injection_test" in decisions:
                        del decisions["sql_injection_test"]
                    reasoning.append("MySQL not confirmed open - SQLMap skipped")
        
        # 4. GIT EXPOSURE CHECK
        web_ports = [s for s in host.services if s.port in [80, 443, 8080, 8443] and s.state == 'open']
        if web_ports:
            decisions["git_check"] = {
                "tool": "git-dumper",
                "reason": "Web server detected - checking for exposed .git directories (common in dev/staging)",
                "priority": "high"
            }
            # Also check for other exposed files
            decisions["exposed_files_scan"] = {
                "tool": "nuclei",
                "reason": "Web server detected - checking for exposed sensitive files (.env, .git, etc.)",
                "priority": "high",
                "tags": "exposure,exposed"
            }
            reasoning.append("Web service: Checking for exposed .git and sensitive files (source code leak risk)")
        
        # 5. CORS MISCONFIGURATION
        if web_ports and host.web_context:
            # Check if it's an API or has JSON responses
            if "api" in str(host.web_context.url).lower() or "json" in str(host.web_context.tech_stack).lower():
                decisions["cors_test"] = {
                    "tool": "cors-tester",
                    "reason": "API endpoint detected - testing for CORS misconfigurations that could allow cross-origin attacks",
                    "priority": "medium"
                }
                reasoning.append("API detected: CORS testing for cross-origin security")
        
        # 6. SUBDOMAIN TAKEOVER
        if dns_info and dns_info.records:
            cnames = dns_info.records.get('CNAME', [])
            if cnames:
                decisions["takeover_check"] = {
                    "tool": "subjack",
                    "reason": "CNAME records found - checking for dangling DNS that could enable subdomain takeover",
                    "priority": "high"
                }
                reasoning.append("CNAME records: Subdomain takeover vulnerability check")
        
        # 7. SECURITY HEADERS & WEB SECURITY
        if web_ports:
            decisions["header_analysis"] = {
                "tool": "security-headers",
                "reason": "Web application - analyzing security headers for defense-in-depth posture",
                "priority": "medium"
            }
            # Always run header scanner too
            decisions["header_scanner"] = {
                "tool": "security-header-scanner",
                "reason": "Web application - comprehensive security header audit",
                "priority": "medium"
            }
            reasoning.append("Web app: Security header analysis for protective controls")
        
        # 8. PROTOCOL-SPECIFIC INTELLIGENCE
        
        # SSH Hardening Check
        ssh_services = [s for s in host.services if s.port == 22 and s.state == 'open']
        if ssh_services:
            reasoning.append("SSH exposed: Checking for hardening and key exchange vulnerabilities")
        
        # SMTP Enumeration
        smtp_services = [s for s in host.services if s.port in [25, 587] and s.state == 'open']
        if smtp_services:
            reasoning.append("SMTP detected: User enumeration and relay testing recommended")
        
        # FTP Security
        ftp_services = [s for s in host.services if s.port == 21 and s.state == 'open']
        if ftp_services:
            reasoning.append("FTP detected: CRITICAL - Insecure protocol, anonymous access test required")
        
        # 9. CONTEXT-BASED PRIORITIZATION
        
        # Edge hosts get lighter scanning
        from ..core.models import HostRole
        if host.classification == HostRole.EDGE:
            # Reduce aggressive scanning on edge
            for tool_key in decisions:
                if decisions[tool_key].get("aggressive"):
                    decisions[tool_key]["aggressive"] = False
                    decisions[tool_key]["reason"] += " [STEALTH MODE: Edge host detected]"
            reasoning.append("Edge/WAF host: Using passive/stealth techniques")
        
        # Internal/Origin hosts can be scanned more thoroughly
        elif host.classification in [HostRole.ORIGIN, HostRole.WEB, HostRole.MAIL]:
            reasoning.append(f"{host.classification.value} host: More aggressive enumeration allowed")
        
        # 10. RISK ACCUMULATION LOGIC & COMPREHENSIVE SCANNING
        open_services = [s for s in host.services if s.state == 'open']
        service_count = len(open_services)
        
        # Always run Nuclei for comprehensive coverage (but prioritize based on findings)
        if web_ports:
            if "comprehensive_scan" not in decisions:
                decisions["comprehensive_scan"] = {
                    "tool": "nuclei",
                    "reason": "Web services detected - running comprehensive vulnerability templates",
                    "priority": "medium",
                    "tags": "cve,exposure,intrusive"
                }
                reasoning.append("Web services: Nuclei comprehensive vulnerability scan")
        
        if service_count > 10:
            reasoning.append(f"ALERT: {service_count} open ports detected - Large attack surface requires comprehensive audit")
            decisions["comprehensive_scan"]["priority"] = "high"
            decisions["comprehensive_scan"]["reason"] = f"Excessive service exposure ({service_count} ports) - running comprehensive vulnerability templates"
        
        # 11. WAF DETECTION IMPACT
        # v16.3: More intrusive - allow more tools even with WAF, but with throttling
        if host.web_context and host.web_context.waf_detected:
            waf_type = host.web_context.waf_type
            waf_name = host.web_context.waf_name
            
            if waf_type == "ACTIVE":
                reasoning.append(f"WAF ACTIVE ({waf_name}): Running tools with throttling (more intrusive mode enabled)")
                # v16.3: Don't disable tools, just mark them for throttling
                # Allow feroxbuster and dirsearch even with WAF
                if "directory_scan" not in decisions and web_ports:
                    decisions["directory_scan"] = {
                        "tool": "dirsearch",
                        "reason": "Web app - directory enumeration (WAF-protected, throttled)",
                        "priority": "medium",
                        "throttle": True
                    }
                if "web_fuzzing" not in decisions and web_ports:
                    decisions["web_fuzzing"] = {
                        "tool": "feroxbuster",
                        "reason": "Web app - web fuzzing (WAF-protected, throttled)",
                        "priority": "low",
                        "throttle": True,
                        "aggressive": False
                    }
            else:
                reasoning.append(f"WAF PASSIVE ({waf_name}): Proceeding with standard scanning")
        
        return {
            "tools_to_run": decisions,
            "reasoning": reasoning,
            "risk_context": {
                "service_count": len(open_services),
                "has_web": bool(web_ports),
                "has_database": bool(db_services),
                "has_cms": bool(host.web_context and host.web_context.cms_detected),
                "waf_present": bool(host.web_context and host.web_context.waf_detected)
            }
        }


class DecisionEngine:
    """Backward compatibility wrapper + legacy analysis"""
    
    @staticmethod
    def analyze(host: Host, dns_info: Optional[DNSInfo] = None) -> List[Finding]:
        """Wrapper to maintain backward compatibility"""
        return DecisionEngine.analyze_host(host)

    @staticmethod
    def analyze_host(host: Host) -> List[Finding]:
        """Legacy host analysis - still used for basic findings"""
        findings = []
        open_services = [s for s in host.services if s.state == 'open']
        
        if open_services:
            findings.append(Finding(
                title=f"Open Ports Detected ({host.hostname or host.ip})",
                category="Network", severity=Severity.INFO,
                description=f"Found {len(open_services)} open ports.", 
                recommendation="Review exposures."
            ))
            
            # Service-specific findings
            for s in open_services:
                if s.name in ['http', 'https', 'http-alt', 'nginx', 'apache']:
                    findings.append(Finding(
                        title=f"Web Service ({s.port})", 
                        category="Network", 
                        severity=Severity.INFO, 
                        description=f"Port {s.port} Open", 
                        recommendation="Check security headers and SSL configuration"
                    ))
                
                if s.port in [21, 23]:
                    findings.append(Finding(
                        title=f"Insecure Service ({s.port})", 
                        category="Network", 
                        severity=Severity.HIGH, 
                        description=f"Port {s.port} uses insecure cleartext protocol", 
                        recommendation="Disable service or migrate to secure alternative (SFTP for FTP, SSH for Telnet)"
                    ))
                
                if s.port == 22:
                    findings.append(Finding(
                        title="SSH Exposed", 
                        category="Network", 
                        severity=Severity.LOW, 
                        description="SSH on Port 22 is publicly accessible", 
                        recommendation="Harden SSH: disable root login, use key auth, consider non-standard port"
                    ))
                
                # Database exposure
                if s.port in [3306, 5432, 27017, 1433]:
                    findings.append(Finding(
                        title=f"Database Exposed ({s.port})",
                        category="Network",
                        severity=Severity.CRITICAL,
                        description=f"Database service on port {s.port} is publicly accessible",
                        recommendation="Move database to private network, restrict access via firewall"
                    ))

        return findings

    @staticmethod
    def analyze_dns(dns_info: DNSInfo) -> List[Finding]:
        """DNS-specific findings"""
        findings = []
        if not dns_info: 
            return []
        
        txt_records = dns_info.records.get('TXT', [])
        has_spf = any('v=spf1' in r for r in txt_records)
        if not has_spf:
            findings.append(Finding(
                title="Missing SPF Record", 
                category="DNS", 
                severity=Severity.MEDIUM, 
                description="No SPF record found - email spoofing possible", 
                recommendation="Add SPF record to prevent email spoofing"
            ))
        
        has_dmarc = any('v=DMARC1' in r for r in txt_records)
        if not has_dmarc:
            findings.append(Finding(
                title="Missing DMARC Policy",
                category="DNS",
                severity=Severity.MEDIUM,
                description="No DMARC policy configured",
                recommendation="Implement DMARC for email authentication"
            ))
        
        if not dns_info.records.get('MX', []):
            findings.append(Finding(
                title="No MX Records", 
                category="DNS", 
                severity=Severity.LOW, 
                description="No MX records configured", 
                recommendation="Add MX records if mail service is required"
            ))
        
        # DNSSEC Check
        if not dns_info.records.get('DNSKEY', []):
            findings.append(Finding(
                title="DNSSEC Not Enabled",
                category="DNS",
                severity=Severity.LOW,
                description="Domain is not protected by DNSSEC",
                recommendation="Consider enabling DNSSEC for DNS integrity"
            ))
             
        return findings
