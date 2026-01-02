from typing import Dict, Any, List, Optional
import sys
import datetime
import uuid
import ipaddress
import socket
import concurrent.futures

from .target import Target
from .models import ScanResult, ScanTarget, Host, DNSInfo, WebContext, Finding, Severity, Service, AIReasoning, EvidenceType
from .ai_client import CognitiveEngine
from .debug import debug_print, debug_section, debug_tool

from ..tools.nmap_runner import NmapTool
from ..tools.whois_runner import WhoisTool
from ..tools.dig_runner import DigTool
from ..tools.web_probes import WhatWebTool, SecurityHeaderTool, BehavioralProbe
from ..tools.cms_scanners import WPScanTool, CMSDetector, JoomlaScanTool, DroopescanTool
from ..tools.discovery import SubdomainTool
from ..tools.ssl_tools import SSLScanTool
from ..tools.advanced_security import (NiktoTool, TestSSLTool, SQLMapDetector, 
                                       GitDumperTool, SubdomainTakeoverTool, 
                                       CORSTesterTool, SecurityHeaderAnalyzer)

from ..analysis.normalizer import Normalizer
from ..analysis.decision_engine import DecisionEngine, IntelligentDecisionEngine
from ..analysis.recommendations import RecommendationEngine
from ..analysis.correlation import CorrelationEngine

from ..tools.vuln_scanners import NucleiTool
from ..tools.directory_brute import DirsearchTool
from ..tools.protocol_scanners import MySQLScanner, SMTPScanner, SSHScanner, FTPScanner, RDPScanner, SMTPEnumTool, MySQLClientTool, SMBScanner, LDAPScanner, RPCScanner, SNMPScanner
from ..tools.web_fuzzers import WebFuzzerTool
from ..tools.dns_scanners import DNSScanner
from ..core.cloudflare_filter import CloudflareFilter
from ..tools.infra_mapper import InfraMapperTool
from .history_manager import HistoryManager

class Orchestrator:
    def __init__(self):
        self.nmap = NmapTool()
        self.whois = WhoisTool()
        self.dig = DigTool()
        self.whatweb = WhatWebTool()
        
        # CMS Scanners
        self.cms_detector = CMSDetector()
        self.wpscan = WPScanTool()
        self.joomscan = JoomlaScanTool()
        self.droopescan = DroopescanTool()
        
        # Discovery & Infrastructure
        self.subdomains = SubdomainTool()
        self.sslscan = SSLScanTool()
        self.nuclei = NucleiTool()
        self.dirsearch = DirsearchTool()
        self.feroxbuster = WebFuzzerTool()
        
        # Protocol-specific scanners
        self.mysql_scanner = MySQLScanner()
        self.smtp_scanner = SMTPScanner()
        self.ssh_scanner = SSHScanner()
        self.ftp_scanner = FTPScanner()
        self.rdp_scanner = RDPScanner()
        self.smtp_enum = SMTPEnumTool()
        self.mysql_client = MySQLClientTool()
        self.smb_scanner = SMBScanner()
        self.ldap_scanner = LDAPScanner()
        self.rpc_scanner = RPCScanner()
        self.snmp_scanner = SNMPScanner()
        self.dns_scanner = DNSScanner()
        self.infra_mapper = InfraMapperTool()
        from ..core.cloudflare_filter import CloudflareFilter
        self.cloudflare_filter = CloudflareFilter()
        
        # v16.2: API Scanner and Config Auditor
        from ..tools.api_scanner import APIScanner
        from ..tools.config_auditor import ConfigAuditor
        self.api_scanner = APIScanner()
        self.config_auditor = ConfigAuditor()
        
        # Advanced Security Tools
        self.nikto = NiktoTool()
        self.testssl = TestSSLTool()
        self.sqlmap = SQLMapDetector()
        self.git_dumper = GitDumperTool()
        self.subjack = SubdomainTakeoverTool()
        self.cors_tester = CORSTesterTool()
        self.sec_headers = SecurityHeaderAnalyzer()
        
        # v14.0 Web Tools
        self.header_scanner = SecurityHeaderTool()
        self.behavioral_probe = BehavioralProbe()
        
        # Intelligence Engines
        self.brain = CognitiveEngine()
        self.decision_engine = IntelligentDecisionEngine()
        self.correlation_engine = CorrelationEngine()
        
        # v16.0: Advanced Intelligence
        from ..intelligence.cve_lookup import CVELookup
        from ..intelligence.pattern_learner import PatternLearner
        from ..intelligence.vulnerability_predictor import VulnerabilityPredictor
        from ..intelligence.adaptive_optimizer import AdaptiveOptimizer
        from ..intelligence.threat_intel import ThreatIntelligence
        from ..core.smart_cache import SmartCache
        from ..core.http_pool import get_http_pool
        
        self.cve_lookup = CVELookup()
        self.pattern_learner = PatternLearner()
        self.vuln_predictor = VulnerabilityPredictor()
        self.adaptive_optimizer = AdaptiveOptimizer()
        self.threat_intel = ThreatIntelligence()
        self.cache = SmartCache()
        self.http_pool = get_http_pool()
        
        self.history = HistoryManager()
        
        # v16.2: Database and Historical Context
        from ..core.database import ScanDatabase
        from ..intelligence.historical_context import HistoricalContext
        from ..analysis.business_risk import BusinessRiskPrioritizer
        self.scan_db = ScanDatabase()
        self.historical_context = HistoricalContext(self.scan_db)
        self.business_risk = BusinessRiskPrioritizer()
        
        # v16.3: Security Analyst (Anomaly Detection & Hypothesis Engine)
        from ..intelligence.anomaly_detector import SecurityAnalyst
        self.security_analyst = SecurityAnalyst()
        
        # v16.4: Deep Dive Investigator and OS Detector
        from ..intelligence.deep_dive import DeepDiveInvestigator
        from ..intelligence.os_detector import OSDetector
        self.deep_dive = DeepDiveInvestigator(self.cve_lookup)
        self.os_detector = OSDetector()
        
        from ..intelligence.audit_profiles import AuditProfileManager
        from ..intelligence.finding_deduplicator import FindingDeduplicator
        self.audit_profiles = AuditProfileManager()
        self.deduplicator = FindingDeduplicator()
        
        # v17.5: Tool Blocker with penalty system
        from ..core.tool_blocker import ToolBlocker
        self.tool_blocker = ToolBlocker()
        
        # v17.5: Serializer for JSON safety
        from ..core.serializer import MeowwareSerializer
        self.serializer = MeowwareSerializer()
        
        # v18.0: Cloud & Container Security
        from ..tools.cloud_auditor import CloudAuditor
        from ..tools.container_scanner import ContainerScanner
        self.cloud_auditor = CloudAuditor()
        self.container_scanner = ContainerScanner()
        
        # v17.0: Exploitation, Evasion, Fuzzing, and Reporting
        from ..exploitation.exploit_engine import ExploitEngine
        from ..exploitation.mitre_attack import MITREAttackChainBuilder
        from ..evasion.waf_bypass import WAFBypass
        from ..fuzzing.intelligent_fuzzer import IntelligentFuzzer
        from ..reporting.executive_report import ExecutiveReporter
        from ..reporting.dashboard import DashboardReporter
        
        self.exploit_engine = ExploitEngine(self.cve_lookup)
        self.mitre_builder = MITREAttackChainBuilder()
        self.waf_bypass = WAFBypass()
        self.intelligent_fuzzer = IntelligentFuzzer()
        self.executive_reporter = ExecutiveReporter()
        self.dashboard_reporter = DashboardReporter()
        
        # v12: TECH TRIGGERS (Enriched)
        self.TECH_TRIGGERS = [
            "apache", "nginx", "iis", "microsoft-httpapi", "wordpress", 
            "drupal", "joomla", "magento", "php", "asp.net", "coldfusion",
            "exim", "postfix", "dovecot", "openssh", "mysql", "postgresql", 
            "redis", "mongodb", "elasticsearch", "tomcat", "jenkins", "powerdns"
        ]
        # v13.0: Internal CVE/Version Exposure Map (Deterministic)
        self.CVE_MAP = {
            "exim": {"4.98": Severity.HIGH, "4.98.2": Severity.LOW},
            "mysql": {"8.0.44": Severity.MEDIUM, "5.7": Severity.HIGH},
            "apache": {"2.4.49": Severity.CRITICAL, "2.4.50": Severity.CRITICAL},
            "powerdns": {"4.9.4": Severity.MEDIUM}
        }
        
        print(f"[*] Initializing Meowware v1.0 'Tulipán' [Professional Security Audit Platform]...", file=sys.stderr)
        print(f"[*] Developed by Carlos Mancera", file=sys.stderr)
        self.check_all_dependencies()
        
        # v17.4: Improved AI Engine status detection (DeepSeek or Ollama)
        import os
        if self.brain.enabled:
            # Check which provider is configured
            api_provider = os.environ.get('LLM_PROVIDER', 'deepseek').lower()
            
            if api_provider == 'deepseek':
                api_key = os.environ.get('DEEPSEEK_API_KEY', '')
                if api_key:
                    print(f"[+] AI Engine: ONLINE (DeepSeek API configured)")
                else:
                    print(f"[!] AI Engine: DISABLED - DEEPSEEK_API_KEY not set (Using Meowware Rule-Based System)")
                    self.brain.enabled = False
            else:
                # Ollama (legacy)
                try:
                    import requests
                    res = requests.get("http://localhost:11434/", timeout=2)
                    if res.status_code == 200:
                        print(f"[+] AI Engine: ONLINE (connected to Localhost LLM)")
                    else:
                        print(f"[!] AI Engine: UNREACHABLE (Using Meowware Rule-Based System)")
                        self.brain.enabled = False
                except:
                    print(f"[!] AI Engine: OFFLINE (Using Meowware Rule-Based System)")
                    self.brain.enabled = False
        else:
            print(f"[!] AI Engine: DISABLED (Using Meowware Rule-Based System)")

    def check_all_dependencies(self):
        """v12.1: Checks all registered tools and logs a status table to stderr."""
        debug_section("DEPENDENCY STATUS CHECK")
        tools = [
            self.nmap, self.subdomains, 
            self.sslscan, self.nuclei, self.dirsearch, self.feroxbuster,
            self.smtp_enum, self.mysql_client
        ]
        
        debug_print(f"{'TOOL':<20} | {'STATUS':<10} | {'ACTIONS'}")
        debug_print("-" * 50)
        for t in tools:
            status = " [✔]" if t.is_available() else " [✖]"
            action = "Ready" if t.is_available() else f"SUDO: apt install {t.name} (or similar)"
            if t.name == "nuclei" and not t.is_available():
                action = "Run: go install nuclei"
            
            debug_print(f"{t.name:<20} | {status:<10} | {action}")
        debug_print("-" * 50 + "\n")

    def _is_waf(self, ip: str) -> bool:
        try:
            w = self.whois.run(ip)
            keywords = ["Cloudflare", "Akamai", "Fastly", "Incapsula", "Sucuri", "Amazon.com", "Google LLC"]
            for k in keywords:
                if k.lower() in w.lower():
                    return True
        except: pass
        return False

    def _resolve_mx(self, domain: str) -> List[tuple]:
        ips = []
        try:
            import subprocess
            cmd = ["dig", "+short", "MX", domain]
            p = subprocess.run(cmd, capture_output=True, text=True)
            for line in p.stdout.splitlines():
                parts = line.split()
                if len(parts) > 1:
                    mx_host = parts[-1].rstrip('.')
                    try:
                        resolved = str(ipaddress.ip_address(socket.gethostbyname(mx_host)))
                        ips.append((mx_host, resolved))
                    except: pass
        except: pass
        return ips

    def _run_protocol_scanners(self, ip: str, service: Service) -> List[Dict[str, Any]]:
        pf = []
        if service.port == 3306: pf = self.mysql_scanner.run(ip, service.port)
        elif service.port in [25, 587, 465]: pf = self.smtp_scanner.run(ip, service.port)
        elif service.port == 22: pf = self.ssh_scanner.run(ip, service.port)
        elif service.port == 21: pf = self.ftp_scanner.run(ip, service.port)
        elif service.port == 3389: pf = self.rdp_scanner.run(ip, service.port)
        elif service.port == 445: pf = self.smb_scanner.run(ip, service.port)
        elif service.port == 389: pf = self.ldap_scanner.run(ip, service.port)
        elif service.port == 111: pf = self.rpc_scanner.run(ip, service.port)
        elif service.port == 161: pf = self.snmp_scanner.run(ip, service.port)
        return pf

    def _is_stealth_required(self, host: Host) -> bool:
        """v13.0: Decides if stealth is required based on host role (EDGE/WAF)."""
        from ..core.models import HostRole
        is_active_waf = host.web_context and host.web_context.waf_detected and host.web_context.waf_type == "ACTIVE"
        return host.classification == HostRole.EDGE or is_active_waf

    def _calculate_stack_similarity(self, h1: Host, h2: Host) -> float:
        if not h1.web_context or not h2.web_context: return 0.0
        s1 = set([t.lower() for t in h1.web_context.tech_stack])
        s2 = set([t.lower() for t in h2.web_context.tech_stack])
        if not s1 or not s2: return 0.0
        intersection = s1.intersection(s2)
        union = s1.union(s2)
        score = len(intersection) / len(union)
        for t in intersection:
            v1 = next((x for x in h1.web_context.tech_stack if t in x.lower()), "")
            v2 = next((x for x in h2.web_context.tech_stack if t in x.lower()), "")
            if v1 == v2 and v1 != "": score += 0.1
        return min(score, 1.0)

    def _audit_host(self, host_model: Host, scan_state: Dict[str, Any], global_findings: List[Finding], global_reasoning: List[AIReasoning], fingerprint_registry: Dict[str, List[str]]):
        """v12: Segmented concurrent host audit."""
        ip = host_model.ip
        
        # v16.2: Skip Cloudflare IPs immediately
        if self.cloudflare_filter.is_cloudflare_ip(ip):
            debug_print(f"\n[Cloudflare Filter] Skipping audit for Cloudflare IP: {ip} ({host_model.hostname})")
            return host_model
        
        # v16.2: Ensure hostname is a string, not a list
        primary_name = host_model.hostname
        if isinstance(primary_name, list):
            primary_name = primary_name[0] if primary_name else ip
        if not primary_name or not isinstance(primary_name, str):
            primary_name = ip
        roles = host_model.roles
        
        debug_print(f"\n[Audit] Initiating security audit for: {ip} ({primary_name})")
        
        if "Main" in roles and self._is_waf(ip):
            # Passive path: still fingerprint CMS and headers even when fronted by WAF
            debug_print(f"  ⚠️  WAF Identified. Running passive header probe.")
            url = f"https://{primary_name}"
            ww = self.whatweb.run(url)
            # v16.1: Ensure tech_versions is a dict, not a string
            tech_versions = ww.get('tech_versions', {})
            if not isinstance(tech_versions, dict):
                tech_versions = {}
            host_model.web_context = WebContext(
                url=url, tech_stack=ww.get('tech_stack', []),
                tech_versions=tech_versions,
                waf_detected=True, waf_name=ww.get('waf_name', 'Unknown WAF'),
                waf_type=ww.get('waf_type', 'PASSIVE'),
                cms_detected=ww.get('cms', ''), headers=ww.get('headers', {})
            )

            # v16.2: WordPress detection - will be handled by decision engine with full enumeration
            # Don't run WPScan here - let decision engine handle it with proper enumeration
            # This ensures plugins/users are enumerated when WordPress is confirmed

            header_findings = self.header_scanner.run(url)
            for hf in header_findings:
                global_findings.append(Finding(
                    title=f"{hf['issue']} ({ip})", category="Web Security", severity=hf['severity'],
                    description=hf['description'], recommendation=hf['recommendation'],
                    confidence_score=0.8, evidence_type=EvidenceType.MISCONFIG
                ))

            global_findings.append(Finding(
                title=f"WAF Active ({primary_name})", category="Defense", severity=Severity.INFO,
                description=f"WAF detected ({host_model.web_context.waf_name}).", recommendation="Pivot to potential origin hosts."
            ))
            # v16.1: Don't return early - continue to decision engine for full analysis
            # Continue to iteration loop below

        iteration = 1
        max_iterations = 5 # v16.3: Increased for more intrusive scanning
        investigation_tickets = 0 
        stop_audit = False
        
        while iteration <= (max_iterations + investigation_tickets) and not stop_audit:
            debug_print(f"  --- Iteration {iteration}/{(max_iterations + investigation_tickets)} ---")
            
            # v18.5: TRACKER - Save finding count at start of iteration to detect progress
            findings_at_start = len([f for f in global_findings if f.title.endswith(f"({ip})")])
            tools_executed_this_iter = 0
            
            # 1. SURVEY & CRITICAL SURFACE PRIORITIZATION
            # v17.5: Enhanced nmap execution with validation and rescan if needed
            if iteration == 1:
                raw_nmap = ""
                try:
                    # v17.5: Use improved nmap with better detection
                    raw_nmap = self.nmap.run(ip, mode="quick")
                    host_model.services = Normalizer.parse_nmap_xml(raw_nmap)
                    
                    # v17.5: Validate that we got meaningful results
                    open_ports = [s for s in host_model.services if s.state == 'open']
                    if len(open_ports) < 1:
                        debug_print(f"    [⚠] Nmap detected <1 open ports, attempting rescan with standard mode...")
                        try:
                            raw_nmap = self.nmap.run(ip, mode="std")
                            host_model.services = Normalizer.parse_nmap_xml(raw_nmap)
                            open_ports = [s for s in host_model.services if s.state == 'open']
                            debug_print(f"    [✓] Rescan detected {len(open_ports)} open ports")
                        except Exception as e2:
                            debug_print(f"    [✖] Rescan failed: {e2}")
                    else:
                        debug_print(f"    [✓] Nmap detected {len(open_ports)} open ports: {[f'{s.port}/{s.name}' for s in open_ports[:10]]}")
                    
                    # v17.5: Log all detected services (including closed/filtered for context)
                    all_services = len(host_model.services)
                    if all_services > 0:
                        debug_print(f"    [ℹ] Total services detected: {all_services} (open: {len(open_ports)})")
                    
                except Exception as e:
                    debug_print(f"    [✖] Nmap execution failed: {e}")
                    raw_nmap = ""
                    host_model.services = []
                
                scan_state[ip]["tools"].append("nmap_survey")
                
                # v18.0: Container & Orchestration Security
                container_findings = self.container_scanner.run(ip, host_model.services)
                if container_findings:
                    global_findings.extend(container_findings)
                    debug_print(f"    [Container Audit] Found {len(container_findings)} container-related issues")

                # 1. EARLY FINGERPRINTING & PROXY DETECTION (v15.0 WhatWeb-First)
                web_ports = [s for s in host_model.services if s.port in [80, 443, 8080, 8443]]
                if web_ports:
                    proto = "https" if any(p.port == 443 for p in web_ports) else "http"
                    url = f"{proto}://{primary_name}"
                    debug_print(f"    [Detection] Running WhatWeb for CMS/WAF detection: {url}")
                    
                    # Step 1: WhatWeb (Primary CMS Detector) - with cache
                    cached_ww = self.cache.get("whatweb", url)
                    if cached_ww:
                        debug_print(f"    [Cache] Using cached WhatWeb results")
                        ww = cached_ww
                    else:
                        ww = self.whatweb.run(url)
                        self.cache.set("whatweb", url, ww)
                    
                    behavioral_data = self.behavioral_probe.run(url)
                    
                    # Step 2: Enhanced CMS Detection (Complements WhatWeb) - with cache
                    cached_cms = self.cache.get("cms_detector", url, {"whatweb": ww})
                    if cached_cms:
                        debug_print(f"    [Cache] Using cached CMS detection results")
                        cms_info = cached_cms
                    else:
                        debug_print(f"    [Detection] Enhancing CMS detection with additional analysis...")
                        cms_info = self.cms_detector.run(url, whatweb_result=ww)
                        self.cache.set("cms_detector", url, cms_info, {"whatweb": ww})
                    
                    # Merge results: WhatWeb is authoritative, CMSDetector enhances
                    detected_cms = cms_info.get('cms', ww.get('cms', ''))
                    cms_version = cms_info.get('version', '')
                    cms_confidence = cms_info.get('confidence', 0.7)
                    cms_source = cms_info.get('source', 'whatweb')
                    
                    # v17.6: Freeze confidence score - don't recalculate dynamically
                    # Store original confidence for later decisions
                    frozen_cms_confidence = cms_confidence
                    
                    if detected_cms:
                        debug_print(f"      ✓ CMS Detected: {detected_cms}" + 
                                  (f" v{cms_version}" if cms_version else "") +
                                  f" (confidence: {frozen_cms_confidence:.0%}, source: {cms_source}) [FROZEN]")
                    
                    tech_versions = ww.get('tech_versions', {})
                    # v16.1: Ensure tech_versions is a dict, not a string
                    if not isinstance(tech_versions, dict):
                        tech_versions = {}
                    
                    # v16.2: Enhanced CVE Lookup for detected versions
                    if tech_versions:
                        debug_print(f"    [CVE Lookup] Checking CVEs for detected technologies...")
                        for tech, version in tech_versions.items():
                            if version:
                                cve_summary = self.cve_lookup.get_cve_summary(tech, version)
                                if cve_summary['total'] > 0:
                                    debug_print(f"      → {tech} {version}: {cve_summary['total']} CVEs found ({cve_summary['critical']} critical, {cve_summary['high']} high)")
                                    
                                    # Add findings for critical/high CVEs
                                    for cve in cve_summary.get('cves', []):
                                        if cve.get('cvss', 0) >= 7.0:  # High or Critical
                                            global_findings.append(Finding(
                                                title=f"{cve.get('id', 'CVE')} - {tech} {version} ({ip})",
                                                category="Vulnerability",
                                                severity=Severity.CRITICAL if cve.get('cvss', 0) >= 9.0 else Severity.HIGH,
                                                description=f"{cve.get('summary', 'No description available')}. CVSS Score: {cve.get('cvss', 'N/A')}",
                                                recommendation=f"Update {tech} to a patched version. See {cve.get('id', 'CVE')} for details.",
                                                confidence_score=0.9,
                                                raw_output=f"CVE: {cve.get('id')}, CVSS: {cve.get('cvss')}, Source: {cve.get('source', 'Unknown')}"
                                            ))
                    
                    # v16.0: Vulnerability Prediction
                    predictions = self.vuln_predictor.predict_vulnerabilities(tech_versions)
                    if predictions:
                        pred_findings = self.vuln_predictor.generate_findings_from_predictions(predictions)
                        global_findings.extend(pred_findings)
                        debug_print(f"    [Prediction] Generated {len(pred_findings)} vulnerability predictions")
                    
                    host_model.web_context = WebContext(
                        url=url,
                        tech_stack=ww.get('tech_stack', []),
                        tech_versions=tech_versions,
                        waf_detected=ww.get('waf_detected', False),
                        waf_name=ww.get('waf_name', ''),
                        waf_type=ww.get('waf_type', 'PASSIVE'),
                        cms_detected=detected_cms,
                        cms_version=cms_version,
                        headers=ww.get('headers', {}),
                        behavioral_fingerprint=behavioral_data
                    )
                    # v17.6: Store frozen confidence in web_context for consistent decisions
                    if hasattr(host_model.web_context, 'cms_confidence'):
                        host_model.web_context.cms_confidence = frozen_cms_confidence
                    else:
                        # Add cms_confidence attribute if not present
                        setattr(host_model.web_context, 'cms_confidence', frozen_cms_confidence)
                    host_model.is_proxy = host_model.web_context.waf_type == "ACTIVE"
                    scan_state[ip]["tools"].append("whatweb")
                    scan_state[ip]["tools"].append("cms_detector")
                    
                    # Add CMS finding if detected
                    if detected_cms:
                        cms_desc = f"{detected_cms} CMS detected"
                        if cms_version:
                            cms_desc += f" (Version: {cms_version})"
                        cms_desc += f". Detection confidence: {cms_confidence:.0%}."
                        
                        # v18.5: Uncertainty Indicator for low-confidence detections
                        title = f"{detected_cms} CMS Identified ({ip})"
                        if cms_confidence < 0.6:
                            title += " (Low Confidence - Verification Pending)"
                            
                        global_findings.append(Finding(
                            title=title,
                            category="CMS",
                            severity=Severity.INFO,
                            description=cms_desc,
                            recommendation=f"Ensure {detected_cms} is kept up-to-date and properly secured.",
                            confidence_score=cms_confidence,
                            evidence_type=EvidenceType.RECON
                        ))
                    
                    if host_model.is_proxy:
                        debug_print(f"    [🛡️] Proxy/WAF Node detected ({host_model.web_context.waf_name}). Pivoting to Software-First audit.")

                    # INTELLIGENT DECISION ENGINE: Decide which tools to run
                    debug_print(f"    [AI Engine] Analyzing context and deciding tools...")
                    
                    # v16.0: Get tool recommendations from pattern learner
                    tech_stack_dict = {t: host_model.web_context.tech_versions.get(t, "") 
                                     for t in host_model.web_context.tech_stack} if host_model.web_context else {}
                    recommendations = self.pattern_learner.recommend_tools(tech_stack_dict, detected_cms)
                    if recommendations:
                        debug_print(f"    [Pattern Learning] Recommended tools: {[r[0] for r in recommendations[:3]]}")
                    
                    decision_result = self.decision_engine.decide_tools(host_model, dns_info=None)
                    tools_to_run = decision_result["tools_to_run"]
                    reasoning = decision_result["reasoning"]
                    
                    # v16.0: Apply pattern learning recommendations (boost recommended tools)
                    for tool_name, confidence in recommendations[:5]:
                        if tool_name in tools_to_run:
                            tools_to_run[tool_name]["priority"] = "high"
                            tools_to_run[tool_name]["reason"] += f" [Recommended by pattern learning: {confidence:.0%} confidence]"
                    
                    # Log AI reasoning
                    for reason in reasoning:
                        debug_print(f"      → {reason}")
                    
                    # Execute decided tools
                    for tool_key, tool_config in tools_to_run.items():
                        tool_name = tool_config["tool"]
                        priority = tool_config["priority"]
                        reason = tool_config["reason"]
                        
                        debug_print(f"    [Execute] {tool_name.upper()} [{priority}]: {reason}")
                        
                        # CMS Scans
                        if tool_name == "wpscan":
                            # v17.6: Use frozen confidence - don't recalculate
                            wp_confirmed = host_model.web_context and host_model.web_context.cms_detected and "wordpress" in host_model.web_context.cms_detected.lower()
                            # v17.6: Get frozen confidence from web_context (set during detection phase)
                            cms_confidence = getattr(host_model.web_context, 'cms_confidence', 0.7) if host_model.web_context else 0.7
                            
                            if wp_confirmed and cms_confidence < 0.6:
                                debug_print(f"    [Block] wpscan skipped: WordPress detection confidence too low ({cms_confidence:.0%}) [Using frozen confidence from detection phase]")
                                scan_state[ip]["tools"].append("wpscan")
                                continue
                            elif wp_confirmed:
                                debug_print(f"    [✓] WordPress confirmed with confidence {cms_confidence:.0%} [FROZEN] - proceeding with WPScan")
                                
                            has_waf = host_model.web_context and host_model.web_context.waf_detected
                            # v16.2: Always use aggressive mode when WordPress confirmed
                            use_aggressive = True if wp_confirmed else tool_config.get("aggressive", False)
                            
                            if wp_confirmed:
                                if has_waf:
                                    debug_print(f"    [WPScan] WordPress confirmed with WAF - attempting enumeration (plugins/users)")
                                else:
                                    debug_print(f"    [WPScan] WordPress confirmed - full enumeration")
                            
                            # v16.2: If WordPress detected on subdomain, also try main domain
                            wp_url = url
                            primary_name = host_model.hostname or host_model.ip
                            if isinstance(primary_name, list):
                                primary_name = primary_name[0] if primary_name else host_model.ip
                            
                            # Extract main domain from subdomain (e.g., mail.webirix.com -> webirix.com)
                            if wp_confirmed and '.' in primary_name and primary_name.count('.') >= 2:
                                parts = primary_name.split('.')
                                # Get last 2 parts (domain.tld)
                                main_domain = '.'.join(parts[-2:])
                                if main_domain != primary_name:
                                    # Try main domain first, then subdomain
                                    main_url = f"https://{main_domain}"
                                    debug_print(f"    [WPScan] WordPress detected on subdomain {primary_name}, also scanning main domain: {main_domain}")
                                    wp_res = self.wpscan.run(main_url, aggressive=use_aggressive, has_waf=has_waf)
                                    if not wp_res:
                                        # If main domain didn't work, try subdomain
                                        debug_print(f"    [WPScan] Main domain scan returned no results, trying subdomain: {primary_name}")
                                        wp_res = self.wpscan.run(wp_url, aggressive=use_aggressive, has_waf=has_waf)
                                else:
                                    wp_res = self.wpscan.run(wp_url, aggressive=use_aggressive, has_waf=has_waf)
                            else:
                                wp_res = self.wpscan.run(wp_url, aggressive=use_aggressive, has_waf=has_waf)
                            if wp_res:
                                for wf in wp_res:
                                    global_findings.append(Finding(
                                        title=f"{wf.get('issue', wf.get('type', 'WP Finding'))} ({ip})", 
                                        category="CMS", severity=wf.get('severity', Severity.MEDIUM),
                                        description=wf.get('description', wf.get('message', '')), 
                                        recommendation=wf.get('recommendation', 'Review WordPress security'),
                                        confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY,
                                        raw_output=wf.get('message', '')  # v16.2: Store evidence
                                    ))
                                debug_print(f"      ✓ WPScan completed: {len(wp_res)} findings (plugins/users enumerated: {use_aggressive})")
                            else:
                                debug_print(f"      ⚠ WPScan returned no results")
                            scan_state[ip]["tools"].append("wpscan")
                        
                        elif tool_name == "joomscan":
                            joomla_res = self.joomscan.run(url)
                            for jf in joomla_res:
                                global_findings.append(Finding(
                                    title=f"{jf['issue']} ({ip})", category="CMS", severity=jf['severity'],
                                    description=jf['description'], recommendation=jf['recommendation'],
                                    confidence_score=0.85, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("joomscan")
                        
                        elif tool_name == "droopescan":
                            cms_type = tool_config.get("cms_type", "drupal")
                            droop_res = self.droopescan.run(url, cms_type=cms_type)
                            for df in droop_res:
                                global_findings.append(Finding(
                                    title=f"{df['issue']} ({ip})", category="CMS", severity=df['severity'],
                                    description=df['description'], recommendation=df['recommendation'],
                                    confidence_score=0.8, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("droopescan")
                        
                        # Web Vulnerability Scans
                        elif tool_name == "nikto":
                            nikto_res = self.nikto.run(url, port=443 if "https" in url else 80)
                            for nf in nikto_res:
                                global_findings.append(Finding(
                                    title=f"{nf['issue']} ({ip})", category="Web Vulnerability", 
                                    severity=nf['severity'], description=nf['description'], 
                                    recommendation=nf['recommendation'],
                                    confidence_score=0.7, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("nikto")
                        
                        # TLS Scanning
                        elif tool_name == "testssl":
                            tls_res = self.testssl.run(url.replace("http://", "").replace("https://", ""), port=443)
                            for tf in tls_res:
                                global_findings.append(Finding(
                                    title=f"{tf['issue']} ({ip})", category="TLS/SSL", 
                                    severity=tf['severity'], description=tf['description'], 
                                    recommendation=tf['recommendation'],
                                    confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("testssl")
                        
                        # SQL Injection Detection
                        elif tool_name == "sqlmap":
                            sql_res = self.sqlmap.run(url, aggressive=False)
                            for sf in sql_res:
                                global_findings.append(Finding(
                                    title=f"{sf['issue']} ({ip})", category="Injection", 
                                    severity=sf['severity'], description=sf['description'], 
                                    recommendation=sf['recommendation'],
                                    confidence_score=0.95, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("sqlmap")
                        
                        # Git Exposure
                        elif tool_name == "git-dumper":
                            git_res = self.git_dumper.run(url)
                            for gf in git_res:
                                global_findings.append(Finding(
                                    title=f"{gf['issue']} ({ip})", category="Exposure", 
                                    severity=gf['severity'], description=gf['description'], 
                                    recommendation=gf['recommendation'],
                                    confidence_score=1.0, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("git-dumper")
                        
                        # CORS Testing
                        elif tool_name == "cors-tester":
                            cors_res = self.cors_tester.run(url)
                            for cf in cors_res:
                                global_findings.append(Finding(
                                    title=f"{cf['issue']} ({ip})", category="Web Security", 
                                    severity=cf['severity'], description=cf['description'], 
                                    recommendation=cf['recommendation'],
                                    confidence_score=0.9, evidence_type=EvidenceType.MISCONFIG
                                ))
                            scan_state[ip]["tools"].append("cors-tester")
                        
                        # Security Headers
                        elif tool_name == "security-headers":
                            header_res = self.sec_headers.run(url)
                            for hf in header_res:
                                global_findings.append(Finding(
                                    title=f"{hf['issue']} ({ip})", category="Web Security", 
                                    severity=hf['severity'], description=hf['description'], 
                                    recommendation=hf['recommendation'],
                                    confidence_score=1.0, evidence_type=EvidenceType.MISCONFIG
                                ))
                            scan_state[ip]["tools"].append("security-headers")
                        
                        # v16.2: API Scanning
                        # v17.0: Enhanced with intelligent fuzzing
                        elif tool_name == "api-scanner":
                            api_res = self.api_scanner.run(url)
                            for af in api_res:
                                global_findings.append(Finding(
                                    title=f"{af['issue']} ({ip})", category="API Security", 
                                    severity=af['severity'], description=af['description'], 
                                    recommendation=af['recommendation'],
                                    confidence_score=0.85, evidence_type=EvidenceType.VULNERABILITY,
                                    raw_output=af.get('evidence', '')
                                ))
                            
                            # v17.0: Intelligent API fuzzing
                            if api_res:
                                debug_print(f"      [Intelligent Fuzzer] API detected, starting intelligent fuzzing...")
                                api_context = {
                                    "api_detected": True,
                                    "api_type": "rest",  # Could be detected from api_scanner results
                                    "method": "GET"
                                }
                                fuzzing_results = self.intelligent_fuzzer.intelligent_fuzz(url, api_context, fuzz_type="api")
                                if fuzzing_results:
                                    debug_print(f"      ✓ Generated {len(fuzzing_results)} intelligent fuzzing payloads")
                                    # Add findings from fuzzing if vulnerabilities found
                                    # (This would be done by executing the fuzzing payloads)
                            
                            scan_state[ip]["tools"].append("api-scanner")
                        
                        # v16.2: Security Configuration Audit
                        elif tool_name == "config-auditor":
                            config_res = self.config_auditor.run(url)
                            for cf in config_res:
                                global_findings.append(Finding(
                                    title=f"{cf['issue']} ({ip})", category="Configuration", 
                                    severity=cf['severity'], description=cf['description'], 
                                    recommendation=cf['recommendation'],
                                    confidence_score=1.0, evidence_type=EvidenceType.MISCONFIG,
                                    raw_output=cf.get('evidence', '')
                                ))
                            scan_state[ip]["tools"].append("config-auditor")
                        
                        # Header Scanner (standard)
                        elif tool_name == "security-header-scanner":
                            header_findings = self.header_scanner.run(url)
                            for hf in header_findings:
                                global_findings.append(Finding(
                                    title=f"{hf['issue']} ({ip})", category="Web Security", severity=hf['severity'],
                                    description=hf['description'], recommendation=hf['recommendation'],
                                    confidence_score=0.9, evidence_type=EvidenceType.MISCONFIG
                                ))
                            scan_state[ip]["tools"].append("security-header-scanner")
                        
                        # Directory Scanning
                        elif tool_name == "dirsearch":
                            dir_res = self.dirsearch.run(url)
                            if dir_res:
                                global_findings.append(Finding(
                                    title=f"Directory Enumeration Results ({ip})", category="Reconnaissance",
                                    severity=Severity.INFO, description=f"Found {len(dir_res)} directories/paths",
                                    recommendation="Review exposed directories and restrict access to sensitive paths",
                                    confidence_score=0.8, evidence_type=EvidenceType.RECON
                                ))
                            scan_state[ip]["tools"].append("dirsearch")
                        
                        # Web Fuzzing
                        elif tool_name == "feroxbuster":
                            # v16.3: More intrusive - allow feroxbuster even with WAF, but with throttling
                            use_throttle = tool_config.get("throttle", False)
                            use_aggressive = tool_config.get("aggressive", False)
                            
                            if use_throttle:
                                debug_print(f"    [🛡️] Running feroxbuster with throttling (WAF-protected mode)")
                                f_res = self.feroxbuster.run(url, aggressive=False, throttle=True)
                            elif use_aggressive:
                                debug_print(f"    [⚡] Running feroxbuster in aggressive mode")
                                f_res = self.feroxbuster.run(url, aggressive=True, throttle=False)
                            else:
                                f_res = self.feroxbuster.run(url, aggressive=False, throttle=False)
                            
                            if f_res: 
                                desc = f"Discovered {len(f_res)} hidden paths via feroxbuster"
                                if use_throttle:
                                    desc += " (WAF-protected, throttled scan)"
                                elif use_aggressive:
                                    desc += " (aggressive mode)"
                                global_findings.append(Finding(
                                    title=f"Exposure Discovery ({ip})", category="Exposure", severity=Severity.MEDIUM, 
                                    description=desc, 
                                    recommendation="Restrict directory access."))
                            scan_state[ip]["tools"].append("feroxbuster")
                        
                        # SSL Scan
                        elif tool_name == "sslscan":
                            ssl_info = self.sslscan.run(url)
                            if ssl_info:
                                host_model.ssl_info = ssl_info
                                # Create findings from SSL info
                                if ssl_info.get('weak_ciphers'):
                                    global_findings.append(Finding(
                                        title=f"Weak SSL Ciphers ({ip})", category="TLS/SSL",
                                        severity=Severity.MEDIUM, description="Weak cipher suites detected",
                                        recommendation="Disable weak ciphers and use only strong TLS configurations",
                                        confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY
                                    ))
                            scan_state[ip]["tools"].append("sslscan")
                        
                        # Nuclei (comprehensive or specific)
                        elif tool_name == "nuclei":
                            tags = tool_config.get("tags", "cve,exposure")
                            n_res = self.nuclei.run(url, tags=tags)
                            for n in n_res:
                                global_findings.append(Finding(
                                    title=f"Nuclei Finding: {n.get('name', 'Vulnerability')} ({ip})", 
                                    category="Vulnerability", 
                                    severity=Severity.HIGH if n.get('severity') == 'high' or n.get('severity') == 'critical' else Severity.MEDIUM, 
                                    description=n.get('description', ''), 
                                    recommendation="Review and patch identified vulnerabilities",
                                    confidence_score=0.85, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("nuclei")
                        
                        # Exposed Files Scan (Nuclei with exposure tags)
                        elif tool_name == "exposed_files_scan":
                            exp_res = self.nuclei.run(url, tags="exposure,exposed")
                            for exp in exp_res:
                                global_findings.append(Finding(
                                    title=f"Exposed File: {exp.get('name', 'Sensitive File')} ({ip})",
                                    category="Exposure", severity=Severity.HIGH,
                                    description=exp.get('description', 'Sensitive file exposed'),
                                    recommendation="Remove or restrict access to exposed files",
                                    confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("exposed_files_scan")
                    
                    # Also run standard header scanner if not already run
                    if "security-header-scanner" not in scan_state[ip]["tools"]:
                        header_findings = self.header_scanner.run(url)
                        for hf in header_findings:
                            global_findings.append(Finding(
                                title=f"{hf['issue']} ({ip})", category="Web Security", severity=hf['severity'],
                                description=hf['description'], recommendation=hf['recommendation'],
                                confidence_score=0.9, evidence_type=EvidenceType.MISCONFIG
                            ))
                    
                    # v16.3: More intrusive - automatically run basic nuclei scan in first iteration
                    if "nuclei" not in scan_state[ip]["tools"]:
                        debug_print(f"    [v16.3] Running initial Nuclei scan for comprehensive coverage...")
                        basic_nuclei = self.nuclei.run(url, tags="cve,exposure")
                        for n in basic_nuclei:
                            global_findings.append(Finding(
                                title=f"Nuclei Finding: {n.get('name', 'Vulnerability')} ({ip})", 
                                category="Vulnerability", 
                                severity=Severity.HIGH if n.get('severity') in ['high', 'critical'] else Severity.MEDIUM, 
                                description=n.get('description', ''), 
                                recommendation="Review and patch identified vulnerabilities",
                                confidence_score=0.85, evidence_type=EvidenceType.VULNERABILITY
                            ))
                        scan_state[ip]["tools"].append("nuclei")

                # 2. PROTOCOL SURFACE & CVE MATCHING
                # v16.3: More intrusive - run protocol scanners even with WAF (but more carefully)
                critical_found = False
                if host_model.is_proxy or self._is_stealth_required(host_model):
                     debug_print(f"    [🛡️] Proxy/Stealth Mode: Running protocol scans with caution on {ip}.")
                     # v16.3: Still run protocol scanners but with reduced aggressiveness
                     for s in host_model.services:
                         if s.state == 'open' and s.port in [3306, 5432, 1433, 27017, 25, 587, 465, 22, 21, 3389, 445, 389]:
                             # Only scan critical ports with WAF
                             p_findings = self._run_protocol_scanners(ip, s)
                             for p in p_findings:
                                 global_findings.append(Finding(
                                     title=f"{p['issue']} ({ip})", category="Critical Protocols", severity=Severity.MEDIUM, 
                                     description=p['description'], recommendation="Harden.",
                                     confidence_score=0.8, evidence_type=EvidenceType.VULNERABILITY
                                 ))
                                 critical_found = True
                else:
                    # v16.3: More aggressive - scan all open ports
                    for s in host_model.services:
                        if s.state == 'open':
                            p_findings = self._run_protocol_scanners(ip, s)
                            for p in p_findings:
                                global_findings.append(Finding(
                                    title=f"{p['issue']} ({ip})", category="Critical Protocols", severity=Severity.MEDIUM, 
                                    description=p['description'], recommendation="Harden.",
                                    confidence_score=0.8, evidence_type=EvidenceType.VULNERABILITY
                                ))
                                critical_found = True
                
                # Deterministic CVE Matching (Always run)
                for s in host_model.services:
                    if s.product.lower() in self.CVE_MAP:
                        v_map = self.CVE_MAP[s.product.lower()]
                        for ver, sev in v_map.items():
                            if ver in s.version:
                                global_findings.append(Finding(
                                    title=f"Intelligent Version Match: {s.product} {s.version} ({ip})",
                                    category="Vuln", severity=sev,
                                    description=f"Deterministic match found in local Meowware DB for {s.product}.",
                                    recommendation="Verify patch status.",
                                    confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY
                                ))
                
                if critical_found:
                    debug_print(f"    [!] Critical protocol surface detected on {ip}. Escalating investigation.")
                    investigation_tickets += 1

                # v13.0: High-Fidelity Infrastructure Clustering & Multi-Role Scoring
                host_model.fingerprint_hash = Normalizer.calculate_fingerprint(host_model.services)
                primary_class, roles_map = Normalizer.classify_host(host_model.services, host_model.web_context)
                host_model.classification = primary_class
                host_model.role_weights = roles_map
                
                # Clustering - Phase 6 Bonus
                cluster_id = Normalizer.get_cluster_id(host_model)
                debug_print(f"    [Classification] Host class: {primary_class.value} | Cluster: {cluster_id[:8]}")

            # 2. AUTONOMOUS MEOWWARE TRIGGERS
            if iteration == 1 and host_model.web_context:
                for t in host_model.web_context.tech_stack:
                    if any(keyword in t.lower() for keyword in self.TECH_TRIGGERS):
                        if "nuclei" not in scan_state[ip]["tools"]:
                            debug_print(f"    [Meowware Trigger] Tech: {t}. Starting Nuclei tech-specific probe...")
                            n_res = self.nuclei.run(host_model.web_context.url, technology=t)
                            for n in n_res:
                                global_findings.append(Finding(title=f"Meowware CVE: {n['name']} ({ip})", category="Vuln", 
                                    severity=Severity.HIGH if n.get('severity') == 'high' else Severity.MEDIUM, 
                                    description=f"Auto-match for {t}: {n.get('description', '')}", recommendation="Update service."))
                            scan_state[ip]["tools"].append("nuclei")

            # 3. SEGMENTED REASONING
            roles_desc = ", ".join([f"{r}:{v}" for r, v in host_model.role_weights.items()])
            ctx = f"Roles: {', '.join(roles)} | Class Weights: {roles_desc}"
            if host_model.web_context: ctx += f" | Tech: {host_model.web_context.tech_stack}"
            
            hist = scan_state[ip]["tools"]
            detailed_findings = [f"{s.port}/{s.name}: {s.product} {s.version} | Banner: {s.banner}" for s in host_model.services]
            findings_so_far = " | ".join(detailed_findings)
            
            insights = []
            for other_ip, other_state in scan_state.items():
                if other_ip == ip: continue
                other_host = other_state.get('host_obj')
                if not other_host: continue

                # v12.5: Host Fingerprint Correlation (Phase 6)
                if host_model.fingerprint_hash and host_model.fingerprint_hash == other_host.fingerprint_hash:
                    insights.append(f"IDENTICAL: Fingerprint match with {other_ip}. Mirrored backend detected.")

                sim = self._calculate_stack_similarity(host_model, other_host)
                if sim > 0.6: insights.append(f"Similar stack to {other_ip} ({sim:.2f})")

            # v16.2: Use LLM if enabled, otherwise use rule-based decision engine
            # v16.2: Track progress real (ports, services, findings)
            progress_tracker = scan_state[ip].setdefault("progress", {
                "ports_found": set(),
                "services_confirmed": set(),
                "findings_count": 0,
                "last_progress_iter": iteration
            })
            
            # v16.4: OS and Technology Stack Detection (First iteration only, then reuse)
            # v17.1: Store tech_stack_info in scan_state to persist across iterations
            if "tech_stack_info" not in scan_state[ip]:
                tech_stack = self.os_detector.detect_os_and_stack(host_model)
                scan_state[ip]["tech_stack_info"] = {
                    "os": tech_stack.os.value,
                    "web_server": tech_stack.web_server,
                    "database": tech_stack.database,
                    "cms": tech_stack.cms,
                    "programming_language": tech_stack.programming_language,
                    "confidence": tech_stack.confidence
                }
                # Store in host_model for easy access
                host_model.tech_stack_info = tech_stack
                debug_print(f"    [OS Detector] Technology Stack: {tech_stack}")
                
                # Get audit priorities based on tech stack
                priorities = self.os_detector.get_audit_priorities(tech_stack)
                if priorities["reasoning"]:
                    for reason in priorities["reasoning"]:
                        debug_print(f"      → {reason}")
            
            # Reuse tech_stack_info from previous iterations
            tech_stack_info = scan_state[ip].get("tech_stack_info")
            
            # v16.3: Security Analyst - Detect anomalies and generate hypotheses BEFORE LLM decision
            analyst_result = self.security_analyst.analyze_host(
                host_model, 
                host_model.services, 
                host_model.web_context,
                iteration
            )
            
            anomalies = analyst_result.get('anomalies', [])
            hypotheses = analyst_result.get('active_hypotheses', [])
            # v17.1: Deduplicate hypotheses by title
            seen_hyp_titles = set()
            unique_hypotheses = []
            for hyp in hypotheses:
                hyp_title = getattr(hyp, 'title', str(hyp))
                if hyp_title not in seen_hyp_titles:
                    seen_hyp_titles.add(hyp_title)
                    unique_hypotheses.append(hyp)
            hypotheses = unique_hypotheses
            
            # v17.3: Mostrar resumen de hipótesis en lugar de lista completa
            if hypotheses and iteration == 1:
                debug_print(f"    [💡] {len(hypotheses)} hipótesis activas generadas")
            
            analyst_reasoning = analyst_result.get('reasoning', '')
            
            if analyst_reasoning:
                debug_print(f"    [Analysis] {analyst_reasoning}")
            
            # v16.3: Add findings from anomalies
            # v17.1: Deduplicate anomalies by type and description
            seen_anomaly_keys = set()
            for anomaly in anomalies:
                anomaly_key = f"{anomaly.type.value}_{ip}"
                if anomaly_key not in seen_anomaly_keys:
                    seen_anomaly_keys.add(anomaly_key)
                    if anomaly.severity in [Severity.CRITICAL, Severity.HIGH]:
                        global_findings.append(Finding(
                            title=f"Anomaly Detected: {anomaly.type.value.replace('_', ' ').title()} ({ip})",
                            category="Anomaly",
                            severity=anomaly.severity,
                            description=anomaly.description,
                            recommendation=anomaly.hypothesis,
                            confidence_score=anomaly.confidence,
                            evidence_type=EvidenceType.RECON,
                            raw_output=str(anomaly.evidence)
                        ))
            
            # v16.4: Deep Dive Investigation - Investigate recent vulnerabilities
            # v17.0: Also search for exploits and build MITRE ATT&CK chains
            # v17.1: Deduplicate findings to avoid deep dive repetition
            recent_findings_raw = [f for f in global_findings if f.title.endswith(f"({ip})")][-5:]  # Last 5 findings
            # Deduplicate by title to avoid investigating same finding multiple times
            seen_titles = set()
            unique_recent_findings = []
            for f in recent_findings_raw:
                if f.title not in seen_titles:
                    seen_titles.add(f.title)
                    unique_recent_findings.append(f)
            
            # v17.5: Serialize findings for LLM using centralized serializer
            recent_findings = []
            for f in unique_recent_findings:
                try:
                    if hasattr(self, 'serializer'):
                        finding_dict = self.serializer.serialize(f)
                    else:
                        # Fallback if serializer not available
                        finding_dict = {
                            'title': f.title,
                            'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                            'category': f.category,
                            'description': f.description[:200] if f.description else ''
                        }
                    if isinstance(finding_dict, dict):
                        if 'description' in finding_dict:
                            finding_dict['description'] = finding_dict['description'][:200]
                        recent_findings.append(finding_dict)
                    else:
                        recent_findings.append({'title': f.title, 'severity': 'UNKNOWN'})
                except Exception as e:
                    debug_print(f"    [⚠] Error serializing finding for LLM: {e}")
                    recent_findings.append({'title': f.title, 'severity': 'UNKNOWN'})
            
            deep_dive_recommendations = []
            exploitable_findings = []
            
            for finding in recent_findings:
                if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                    investigation = self.deep_dive.investigate_finding(finding, host_model)
                    
                    # Add CVEs found to findings
                    for cve in investigation.get("cves_found", [])[:3]:  # Top 3 CVEs
                        if cve.get('cvss', 0) >= 7.0:  # High/Critical CVEs
                            global_findings.append(Finding(
                                title=f"{cve.get('id', 'CVE')} - {finding.title} ({ip})",
                                category="Vulnerability",
                                severity=Severity.CRITICAL if cve.get('cvss', 0) >= 9.0 else Severity.HIGH,
                                description=f"CVE found for {finding.title}: {cve.get('summary', '')[:200]}. CVSS: {cve.get('cvss', 'N/A')}",
                                recommendation=f"Review and patch {cve.get('id', 'CVE')}. See CVE database for details.",
                                confidence_score=0.95,
                                evidence_type=EvidenceType.VULNERABILITY,
                                raw_output=f"CVE: {cve.get('id')}, CVSS: {cve.get('cvss')}, Source: {cve.get('source', 'Unknown')}"
                            ))
                    
                    # v17.0: Search for exploits
                    exploit = self.exploit_engine.find_exploit(finding, host_model)
                    if exploit:
                        exploitable_findings.append((finding, exploit))
                        debug_print(f"      [Exploit Engine] Exploit found: {exploit.get('source')} for {finding.title}")
                        # Add exploit finding
                        global_findings.append(Finding(
                            title=f"Exploit Available: {finding.title} ({ip})",
                            category="Exploitation",
                            severity=Severity.CRITICAL if finding.severity == Severity.CRITICAL else Severity.HIGH,
                            description=f"Exploit available from {exploit.get('source')}. {exploit.get('exploit', {}).get('instructions', 'Manual execution required.')}",
                            recommendation="Immediate patching required. Exploit is publicly available.",
                            confidence_score=0.9,
                            evidence_type=EvidenceType.VULNERABILITY,
                            raw_output=str(exploit)
                        ))
                    
                    # v17.1: Seguimiento automático de cadenas de ataque
                    # Si encuentra SQL Injection, ejecutar SQLMap automáticamente
                    if ("SQL Injection" in finding.title or "SQLi" in finding.title or 
                        "sql injection" in finding.description.lower() or
                        "sqli" in finding.description.lower()):
                        if host_model.web_context and "sqlmap" not in scan_state[ip]["tools"]:
                            debug_print(f"      [Attack Chain] SQL Injection detected - automatically running SQLMap")
                            url = host_model.web_context.url
                            sqlmap_res = self.sqlmap.run(url, aggressive=False)
                            for sf in sqlmap_res:
                                global_findings.append(Finding(
                                    title=f"{sf['issue']} ({ip})", category="Injection", 
                                    severity=sf['severity'], description=sf['description'], 
                                    recommendation=sf['recommendation'],
                                    confidence_score=0.95, evidence_type=EvidenceType.VULNERABILITY
                                ))
                            scan_state[ip]["tools"].append("sqlmap")
                    
                    # Si encuentra MySQL expuesto, intentar conexión automática
                    if ("MySQL" in finding.title and "exposed" in finding.title.lower()) or \
                       ("3306" in finding.title and "exposed" in finding.title.lower()) or \
                       ("Exposed Sensitive Service" in finding.title and "3306" in str(finding.description)):
                        if "mysql-client" not in scan_state[ip]["tools"]:
                            debug_print(f"      [Attack Chain] MySQL exposed detected - automatically testing connection")
                            # Ejecutar mysql-client automáticamente
                            try:
                                m_res = self.mysql_client.run(ip)
                                for mf in m_res:
                                    global_findings.append(Finding(
                                        title=f"{mf.get('issue', 'MySQL Connection Test')} ({ip})", 
                                        category="Database", 
                                        severity=mf.get('severity', Severity.MEDIUM), 
                                        description=mf.get('description', ''), 
                                        recommendation=mf.get('recommendation', 'Review MySQL access controls'),
                                        confidence_score=0.9, evidence_type=EvidenceType.VULNERABILITY
                                    ))
                                scan_state[ip]["tools"].append("mysql-client")
                                debug_print(f"      [Attack Chain] mysql-client executed automatically")
                            except Exception as e:
                                debug_print(f"      [Attack Chain] mysql-client execution failed: {e}")
                                deep_dive_recommendations.append("mysql-client")
                    
                    # Collect recommended tools for deep dive
                    deep_dive_recommendations.extend(investigation.get("recommended_tools", []))
                    
                    # v17.3: Log investigation results (solo en primera iteración o si es crítico)
                    if iteration == 1 or finding.severity == Severity.CRITICAL:
                        if investigation.get("attack_vectors"):
                            vectors = ', '.join(investigation['attack_vectors'][:2])
                            debug_print(f"      [🔍 Deep Dive] Vectores: {vectors}")
                        if investigation.get("exploitability") != "unknown":
                            exp = investigation['exploitability']
                            debug_print(f"      [🔍 Deep Dive] Exploitabilidad: {exp}")
            
            # v17.0: Build MITRE ATT&CK chain if exploitable findings exist
            if exploitable_findings and iteration == 1:
                try:
                    chain = self.mitre_builder.build_chain(host_model, [f for f, _ in exploitable_findings])
                    chain_summary = self.mitre_builder.get_chain_summary(chain)
                    debug_print(f"      [MITRE ATT&CK] Chain built: {chain_summary['steps_completed']}/{chain_summary['total_steps']} steps, Impact: {chain_summary['impact_score']:.2f}")
                    # Store chain for later reporting
                    if not hasattr(host_model, 'mitre_chains'):
                        host_model.mitre_chains = []
                    host_model.mitre_chains.append(chain)
                except Exception as e:
                    debug_print(f"      ⚠️  MITRE ATT&CK chain building failed: {e}")
            
            # Remove duplicates from recommendations
            deep_dive_recommendations = list(set(deep_dive_recommendations))[:5]  # Top 5 unique
            
            # v17.0: Apply WAF bypass if WAF detected
            if host_model.web_context and host_model.web_context.waf_detected:
                # WAF bypass will be applied automatically in requests
                debug_print(f"      [WAF Bypass] WAF detected ({host_model.web_context.waf_name}), bypass techniques will be applied")
            
            # v17.5: Decrement exclusions after each iteration
            if hasattr(self, 'tool_blocker'):
                self.tool_blocker.decrement_exclusions(ip)
            
            if self.brain.enabled:
                try:
                    # v16.2: Get historical context for LLM
                    hist_context = self.historical_context.get_context_for_target(host_model.hostname or host_model.ip)
                    # v16.4: Pass tech stack, recent findings, and deep dive recommendations to LLM
                    # v17.5: Get blocked tools list for this IP
                    blocked_tools_list = []
                    if hasattr(self, 'tool_blocker'):
                        blocked_tools_list = self.tool_blocker.get_blocked_list(ip)
                    
                    decision = self.brain.decide(
                        host_model, 
                        context=ctx, 
                        history=hist, 
                        findings_summary=findings_so_far, 
                        iteration=iteration, 
                        historical_context=hist_context,
                        anomalies=anomalies,
                        hypotheses=hypotheses,
                        tech_stack=tech_stack_info,
                        recent_findings=recent_findings,
                        deep_dive_recommendations=deep_dive_recommendations,
                        blocked_tools=blocked_tools_list  # v17.5: Pass blocked tools
                    )
                    # v16.2: Extract single tool from new format
                    # v17.4: Safe access with None checks
                    tool_decision = decision.get('decision') or {}
                    if not isinstance(tool_decision, dict):
                        tool_decision = {}
                    
                    tool_value = tool_decision.get('tool')
                    if isinstance(tool_value, str) and tool_value:
                        selected_tool = tool_value
                        tools_list = [selected_tool] if selected_tool != "stop" else []
                    else:
                        # Fallback: take first tool from list (legacy format)
                        tools_list = (tool_decision.get('tools') or [])[:1]  # v16.2: MAX 1 TOOL
                    
                    # v17.1: Handle empty LLM response
                    # v17.3: Mensaje más claro
                    # v17.4: Safe check for empty tool
                    tool_val = tool_decision.get('tool') if isinstance(tool_decision, dict) else None
                    if not tools_list or (isinstance(tool_val, str) and tool_val == ''):
                        debug_print(f"    [⚠] LLM respuesta vacía, usando fallback")
                        # Try hypothesis-recommended tools first
                        if hypotheses:
                            hyp_tools = []
                            for hyp in hypotheses[:2]:  # Top 2 hypotheses
                                hyp_tools.extend(hyp.recommended_tools[:2])  # Top 2 tools per hypothesis
                            tools_list = list(set(hyp_tools))[:1]  # Unique, max 1
                            if tools_list:
                                debug_print(f"    [Fallback] Using hypothesis-recommended tool: {tools_list[0]}")
                        # If still no tools, try deep dive recommendations
                        if not tools_list and deep_dive_recommendations:
                            tools_list = [deep_dive_recommendations[0]] if deep_dive_recommendations else []
                            if tools_list:
                                debug_print(f"    [Fallback] Using deep-dive recommended tool: {tools_list[0]}")
                    
                    # v16.3: If no tool from LLM but hypotheses exist, use hypothesis-recommended tools
                    if not tools_list and hypotheses:
                        hyp_tools = []
                        for hyp in hypotheses[:2]:  # Top 2 hypotheses
                            hyp_tools.extend(hyp.recommended_tools[:2])  # Top 2 tools per hypothesis
                        tools_list = list(set(hyp_tools))[:1]  # Unique, max 1
                        if tools_list:
                            debug_print(f"    [Fallback] Using hypothesis-recommended tool: {tools_list[0]}")
                    
                    # v1.0: Show analyst insight if available (simplified)
                    analyst_insight = decision.get('analyst_insight', '')
                    if analyst_insight and iteration == 1:  # Only show on first iteration
                        debug_print(f"    [Insight] {analyst_insight[:100]}")
                    
                    # v17.3: Mensaje más claro
                    # v17.4: Safe access to reason field
                    if tools_list:
                        tool_name = tools_list[0]
                        reason = tool_decision.get('reason') or 'Sin razón especificada'
                        if isinstance(reason, str):
                            debug_print(f"    [Decision] {tool_name} - {reason[:60]}")
                        else:
                            debug_print(f"    [Decision] {tool_name}")
                    else:
                        debug_print(f"    [Decision] STOP (no tools suggested)")
                except Exception as e:
                    debug_print(f"    [⚠] Decision engine error: {str(e)[:100]}, using fallback")
                    decision_result = self.decision_engine.decide_tools(host_model, dns_info=None)
                    tools_list = list(decision_result["tools_to_run"].keys())[:1]  # v16.2: MAX 1 TOOL
                    decision = {
                        "decision": {"tool": tools_list[0] if tools_list else "stop", "tools": tools_list},
                        "evidence_summary": "Rule-based fallback",
                        "stop": not tools_list
                    }
            else:
                # v17.4: Intelligent fallback using audit profiles
                next_tool = self.audit_profiles.get_intelligent_fallback(
                    host_model, tech_stack_info or {}, scan_state[ip]["tools"], 
                    [f for f in global_findings if ip in f.title]
                )
                if next_tool:
                    tools_list = [next_tool]
                    decision = {
                        "decision": {"tool": next_tool, "tools": tools_list},
                        "evidence_summary": "Audit profile recommendation",
                        "stop": False
                    }
                else:
                    # Final fallback: rule-based engine
                    decision_result = self.decision_engine.decide_tools(host_model, dns_info=None)
                    tools_list = list(decision_result["tools_to_run"].keys())[:1]  # v16.2: MAX 1 TOOL
                    decision = {
                        "decision": {"tool": tools_list[0] if tools_list else "stop", "tools": tools_list},
                        "evidence_summary": "Rule-based fallback",
                        "stop": not tools_list
                    }
            
            # v16.2: Block tools already executed (HARD BLOCK)
            # v17.5: Pre-validate tools against actual detected services BEFORE blocking
            original_tools_list = tools_list.copy()
            
            # v17.5: Validate tool requirements against ACTUAL detected ports
            validated_tools = []
            open_ports = [s.port for s in host_model.services if s.state == 'open']
            open_port_set = set(open_ports)
            
            for tool in tools_list:
                tool_valid = True
                
                # Validate tool requirements
                if tool == "smtp-user-enum":
                    if not open_port_set.intersection({25, 587, 465}):
                        debug_print(f"    [⚠] Tool '{tool}' requires SMTP ports (25/587/465) but none detected")
                        tool_valid = False
                elif tool == "mysql-client":
                    if 3306 not in open_port_set:
                        debug_print(f"    [⚠] Tool '{tool}' requires port 3306 but not detected")
                        tool_valid = False
                elif tool == "dns_scanner":
                    if 53 not in open_port_set:
                        debug_print(f"    [⚠] Tool '{tool}' requires port 53 but not detected")
                        tool_valid = False
                elif tool in ["dirsearch", "feroxbuster", "nikto", "nuclei"]:
                    if not open_port_set.intersection({80, 443, 8080, 8443}):
                        debug_print(f"    [⚠] Tool '{tool}' requires web ports (80/443) but none detected")
                        tool_valid = False
                elif tool == "ftp_scanner":
                    if 21 not in open_port_set:
                        debug_print(f"    [⚠] Tool '{tool}' requires port 21 but not detected")
                        tool_valid = False
                elif tool == "wpscan":
                    # WordPress should be detected in tech_stack or web_context
                    has_wordpress = (host_model.web_context and 
                                   host_model.web_context.cms_detected and 
                                   "wordpress" in host_model.web_context.cms_detected.lower())
                    if not has_wordpress:
                        debug_print(f"    [⚠] Tool '{tool}' requires WordPress detection but not confirmed")
                        tool_valid = False
                
                if tool_valid:
                    validated_tools.append(tool)
            
            tools_list = validated_tools
            
            # v17.5: STRICT blocking - also check for tool name variations
            blocked_tools = []
            for tool in tools_list:
                # Check exact match
                if tool in scan_state[ip]["tools"]:
                    blocked_tools.append(tool)
                # Check for variations (e.g., "cms_scan" vs "cms_detector")
                elif tool == "cms_detector" and "cms_scan" in scan_state[ip]["tools"]:
                    blocked_tools.append(tool)
                elif tool == "cms_scan" and "cms_detector" in scan_state[ip]["tools"]:
                    blocked_tools.append(tool)
                # Check for nuclei variations
                elif tool.startswith("nuclei") and any(t.startswith("nuclei") for t in scan_state[ip]["tools"]):
                    blocked_tools.append(tool)
            
            tools_list = [t for t in tools_list if t not in blocked_tools]
            
            # v17.5: If tool was blocked, log clearly and track repetition
            if blocked_tools:
                debug_print(f"    [🚫 BLOQUEADO] Herramienta(s) ya ejecutada(s): {', '.join(blocked_tools)}")
                debug_print(f"    [ℹ] Herramientas ejecutadas previamente: {', '.join(scan_state[ip]['tools'][:10])}")
                
                # v17.5: Track blocked tool repetition to prevent infinite loops
                if not hasattr(scan_state[ip], 'blocked_tool_count'):
                    scan_state[ip]['blocked_tool_count'] = {}
                
                for bt in blocked_tools:
                    scan_state[ip]['blocked_tool_count'][bt] = scan_state[ip]['blocked_tool_count'].get(bt, 0) + 1
                    
                    # If same tool blocked 3+ times, force rotation
                    if scan_state[ip]['blocked_tool_count'][bt] >= 3:
                        debug_print(f"    [🔄] Tool '{bt}' blocked {scan_state[ip]['blocked_tool_count'][bt]} times - forcing alternative")
                        # Remove from available actions for this iteration
                        if bt in tools_list:
                            tools_list.remove(bt)
                        
                        # Force alternative tool based on context
                        if bt.startswith("cms") or bt == "cms_detector":
                            # Try web tools instead
                            if open_port_set.intersection({80, 443}) and "nikto" not in scan_state[ip]["tools"]:
                                tools_list = ["nikto"]
                                debug_print(f"    [✓] Rotating to nikto instead of {bt}")
                        elif bt == "nuclei":
                            # Try directory enumeration instead
                            if open_port_set.intersection({80, 443}) and "dirsearch" not in scan_state[ip]["tools"]:
                                tools_list = ["dirsearch"]
                                debug_print(f"    [✓] Rotating to dirsearch instead of nuclei")
            
            # v17.5: If LLM suggested blocked tool, try intelligent fallback
            if blocked_tools and not tools_list:
                debug_print(f"    [⚠] LLM suggested blocked tool(s): {', '.join(blocked_tools)}")
                debug_print(f"    [🔄] Attempting intelligent fallback...")
                
                # Try hypothesis-recommended tools
                if hypotheses:
                    hyp_tools = []
                    for hyp in hypotheses[:2]:
                        hyp_tools.extend([t for t in hyp.recommended_tools[:3] if t not in scan_state[ip]["tools"]])
                    if hyp_tools:
                        tools_list = list(set(hyp_tools))[:1]
                        debug_print(f"    [✓] Fallback: Using hypothesis-recommended tool: {tools_list[0]}")
                
                # Try deep dive recommendations
                if not tools_list and deep_dive_recommendations:
                    fallback_tools = [t for t in deep_dive_recommendations[:3] if t not in scan_state[ip]["tools"]]
                    if fallback_tools:
                        tools_list = [fallback_tools[0]]
                        debug_print(f"    [✓] Fallback: Using deep-dive recommended tool: {tools_list[0]}")
                
                # Try audit profile fallback
                if not tools_list:
                    next_tool = self.audit_profiles.get_intelligent_fallback(
                        host_model, tech_stack_info or {}, scan_state[ip]["tools"],
                        [f for f in global_findings if ip in f.title]
                    )
                    if next_tool:
                        tools_list = [next_tool]
                        debug_print(f"    [✓] Fallback: Using audit profile tool: {tools_list[0]}")
            
            # v17.5: Enhanced blocking - prevent repeated suggestions
            # Si es nuclei, también rechazar variantes con tags
            if "nuclei" in scan_state[ip]["tools"]:
                tools_list = [t for t in tools_list if not t.startswith("nuclei")]
                if any(t.startswith("nuclei") for t in original_tools_list):
                    debug_print(f"    [⚠] Variantes de nuclei rechazadas (nuclei ya ejecutado)")
            
            # v17.5: Prevent cms_detector/cms_scan repetition
            if "cms_detector" in scan_state[ip]["tools"] or "cms_scan" in scan_state[ip]["tools"]:
                tools_list = [t for t in tools_list if not t.startswith("cms")]
                if any(t.startswith("cms") for t in original_tools_list):
                    debug_print(f"    [⚠] Variantes de CMS scanner rechazadas (cms_detector/cms_scan ya ejecutado)")
            
            # v17.1: Verificar si hay razones para continuar
            has_active_hypotheses = len(host_model.ai_reasoning.hypotheses) > 0 if hasattr(host_model, 'ai_reasoning') and host_model.ai_reasoning else False
            has_uninvestigated_anomalies = len([a for a in (getattr(host_model, 'anomalies', []) or []) if not getattr(a, 'investigated', False)]) > 0
            has_critical_findings = len([f for f in global_findings if f.title.endswith(f"({ip})") and f.severity in [Severity.CRITICAL, Severity.HIGH]]) > 0
            
            if not tools_list and not decision.get('stop', False):
                # v17.1: No detenerse si hay razones para continuar
                if has_active_hypotheses or has_uninvestigated_anomalies or has_critical_findings:
                    debug_print(f"    [Continue] Active hypotheses: {has_active_hypotheses}, Uninvestigated anomalies: {has_uninvestigated_anomalies}, Critical findings: {has_critical_findings}")
                    # Intentar usar herramientas alternativas o específicas para las hipótesis
                    if has_uninvestigated_anomalies and "mysql-client" not in scan_state[ip]["tools"]:
                        tools_list = ["mysql-client"]  # Forzar herramienta para investigar anomalía
                        debug_print(f"    [Force Tool] Adding mysql-client to investigate MySQL exposure anomaly")
                    elif has_active_hypotheses and "nuclei" not in scan_state[ip]["tools"]:
                        # Usar nuclei con tags específicos para las hipótesis
                        tools_list = ["nuclei"]
                        debug_print(f"    [Force Tool] Adding nuclei to investigate active hypotheses")
                else:
                    debug_print(f"    [Block] All suggested tools already executed. Stopping.")
                    decision['stop'] = True
            
            confidence = 0.7  # v16.2: Don't rely on LLM confidence
            
            # v16.2: Progress Real Check (ports, services, findings)
            current_ports = set([s.port for s in host_model.services if s.state == 'open'])
            current_services = set([f"{s.port}/{s.name}" for s in host_model.services if s.state == 'open'])
            current_findings = len([f for f in global_findings if f.title.endswith(f"({ip})")])
            
            # v18.5: SMART STOP - Check for real progress in this iteration
            new_ports = current_ports - progress_tracker["ports_found"]
            new_services = current_services - progress_tracker["services_confirmed"]
            new_findings_count = current_findings - findings_at_start
            
            has_progress = len(new_ports) > 0 or len(new_services) > 0 or new_findings_count > 0
            
            if has_progress:
                progress_tracker["ports_found"].update(new_ports)
                progress_tracker["services_confirmed"].update(new_services)
                progress_tracker["findings_count"] = current_findings
                progress_tracker["last_progress_iter"] = iteration
                debug_print(f"    [Progress] Iter {iteration} found NEW data: {len(new_ports)} ports, {len(new_services)} services, {new_findings_count} findings")
            else:
                iterations_without_progress = iteration - progress_tracker["last_progress_iter"]
                # v18.5: Stop if 2 consecutive iterations find NOTHING new
                if iterations_without_progress >= 2:
                    debug_print(f"    [Smart Stop] No new findings for {iterations_without_progress} iterations. Terminating audit.")
                    stop_audit = True
            
            # v13.0: Critical Evidence Override (Keep going if AXFR/Exposure found)
            critical_evidence = any("AXFR" in f.title or "EXPOSURE" in f.category.upper() or f.severity == Severity.CRITICAL for f in global_findings if f.title.endswith(f"({ip})"))
            if critical_evidence:
                progress_tracker["last_progress_iter"] = iteration  # Reset counter

            reason = AIReasoning(
                context=f"IP: {ip} (Iter {iteration})",
                host_class=host_model.classification.value if hasattr(host_model, 'classification') else 'UNKNOWN',
                analysis={},
                hypotheses=[],
                verification_goals=[],
                tools_selected=tools_list,
                stop_decision=stop_audit or decision.get('stop', False),
                stop_reason="No progress" if stop_audit else decision.get('stop_reason', "Cycle complete."),
                evidence_summary=decision.get('evidence_summary', ""),
                interpretation=decision.get('decision', {}).get('reason', ""),
                confidence=confidence,
                iteration=iteration,
                infrastructure_insights=insights
            )
            global_reasoning.append(reason)
            
            if reason.stop_decision or iteration >= 5:
                stop_audit = True
                break

            # v16.2: ADVANCED ACTION EXECUTION - ONE TOOL ONLY
            # v16.2: HARD BLOCK - tools already executed are skipped
            for t_name in tools_list:
                if t_name in scan_state[ip]["tools"]:
                    debug_print(f"    [Block] {t_name} already executed. Skipping.")
                    continue
                
                # v12.5: Tool Dedup Engine (Phase 6 Bonus)
                f_hash = host_model.fingerprint_hash
                if f_hash:
                    executed_on_this_f = fingerprint_registry.setdefault(f_hash, [])
                    if t_name in executed_on_this_f:
                        debug_print(f"    [Dedup] Skipping {t_name} (already verified on fingerprint {f_hash[:8]})")
                        scan_state[ip]["tools"].append(t_name)
                        continue
                    executed_on_this_f.append(t_name)

                debug_print(f"    [Execute] {t_name}...")
                
                if t_name == "nuclei":
                    # v17.4: Safe access to tags field
                    tags_raw = decision.get('decision', {}) or {}
                    if not isinstance(tags_raw, dict):
                        tags_raw = {}
                    tags = tags_raw.get('tags') or 'exposure'
                    # Ensure tags is a string
                    if not isinstance(tags, str):
                        tags = str(tags) if tags else 'exposure'
                    
                    # v17.1: Validar y filtrar tags según tech stack real
                    # Si no hay web_context, usar tags genéricos
                    if not host_model.web_context:
                        tags = "exposure,cve,misconfig"
                        debug_print(f"    [Nuclei] No web context - using generic tags: {tags}")
                    else:
                        tags = self._validate_nuclei_tags(tags, host_model)
                        debug_print(f"    [Nuclei] Using validated tags: {tags}")
                    n_res = self.nuclei.run(host_model.web_context.url if host_model.web_context else f"http://{ip}", tags=tags)
                    for n in n_res:
                        global_findings.append(Finding(title=f"Exploit Match ({ip})", category="Exploit", severity=Severity.HIGH, 
                                                      description=n['name'], recommendation="Mitigate exposure."))
                elif t_name == "feroxbuster" and host_model.web_context:
                    if host_model.web_context.waf_type == "ACTIVE":
                        debug_print(f"    [🛡️] ACTIVE WAF Scaling: feroxbuster restricted to passive-only/safe mode.")
                        # In a real scenario, we might add '-n' or just skip. 
                        # For now, let's skip aggressive fuzzing on ACTIVE WAF.
                        global_findings.append(Finding(title=f"Fuzzing Skipped ({ip})", category="Security", severity=Severity.INFO, 
                                                        description="Aggressive fuzzing was skipped due to an ACTIVE WAF detected.", recommendation="Perform manual slow-throttle audit."))
                    else:
                        f_res = self.feroxbuster.run(host_model.web_context.url)
                        if f_res: global_findings.append(Finding(title=f"Exposure Discovery ({ip})", category="Exposure", severity=Severity.MEDIUM, 
                                                                description=f"Discovered {len(f_res)} hidden paths via feroxbuster.", recommendation="Restrict directory access."))
                elif t_name == "smtp-user-enum":
                    # v16.2: Only if port 25/587 confirmed open
                    smtp_ports = [s.port for s in host_model.services if s.port in [25, 587] and s.state == 'open']
                    if not smtp_ports:
                        debug_print(f"    [Block] SMTP port not confirmed open. Skipping.")
                        scan_state[ip]["tools"].append(t_name)
                        continue
                    enum_res = self.smtp_enum.run(ip)
                    for e in enum_res: global_findings.append(Finding(title=e['issue'], category="Mail", severity=Severity.MEDIUM, description=e['description'], recommendation="Disable VRFY."))
                elif t_name == "mysql-client":
                    # v16.2: Only if port 3306 confirmed open
                    mysql_ports = [s.port for s in host_model.services if s.port == 3306 and s.state == 'open']
                    if not mysql_ports:
                        debug_print(f"    [Block] MySQL port 3306 not confirmed open. Skipping.")
                        scan_state[ip]["tools"].append(t_name)
                        continue
                    m_res = self.mysql_client.run(ip)
                    for m in m_res: global_findings.append(Finding(title=m['issue'], category="Database", severity=Severity.CRITICAL, description=m['description'], recommendation="Set root password."))
                elif t_name == "wpscan" and host_model.web_context:
                    # v16.2: Only if WordPress confirmed
                    if not host_model.web_context.cms_detected or "wordpress" not in host_model.web_context.cms_detected.lower():
                        debug_print(f"    [Block] WordPress not confirmed. Skipping WPScan.")
                        scan_state[ip]["tools"].append(t_name)
                        continue
                    
                    # v16.2: Check if already executed
                    if "wpscan" in scan_state[ip]["tools"]:
                        debug_print(f"    [Block] WPScan already executed. Skipping.")
                        continue
                    
                    # v16.2: WordPress confirmed - enumerate plugins/users even with WAF
                    has_waf = host_model.web_context.waf_detected
                    if has_waf:
                        debug_print(f"    [WPScan] WordPress confirmed with WAF - attempting enumeration (plugins/users)")
                    else:
                        debug_print(f"    [WPScan] WordPress confirmed - full enumeration (plugins/themes/users)")
                    
                    # v16.2: Use aggressive mode to enumerate plugins, themes, users
                    # If WordPress detected on subdomain, also try main domain
                    wp_url = host_model.web_context.url
                    primary_name = host_model.hostname or host_model.ip
                    if isinstance(primary_name, list):
                        primary_name = primary_name[0] if primary_name else host_model.ip
                    
                    # Extract main domain from subdomain (e.g., mail.webirix.com -> webirix.com)
                    if '.' in primary_name and primary_name.count('.') >= 2:
                        parts = primary_name.split('.')
                        # Get last 2 parts (domain.tld)
                        main_domain = '.'.join(parts[-2:])
                        if main_domain != primary_name:
                            # Try main domain first, then subdomain
                            main_url = f"https://{main_domain}"
                            debug_print(f"    [WPScan] WordPress detected on subdomain {primary_name}, also scanning main domain: {main_domain}")
                            wp_res = self.wpscan.run(main_url, aggressive=True, has_waf=has_waf)
                            if not wp_res:
                                # If main domain didn't work, try subdomain
                                debug_print(f"    [WPScan] Main domain scan returned no results, trying subdomain: {primary_name}")
                                wp_res = self.wpscan.run(wp_url, aggressive=True, has_waf=has_waf)
                        else:
                            wp_res = self.wpscan.run(wp_url, aggressive=True, has_waf=has_waf)
                    else:
                        wp_res = self.wpscan.run(wp_url, aggressive=True, has_waf=has_waf)
                    
                    if wp_res:
                        # v17.6: Verify WordPress detection after WPScan
                        wp_actually_detected = any(
                            'wordpress' in str(wf.get('issue', '')).lower() or
                            'wordpress' in str(wf.get('description', '')).lower()
                            for wf in wp_res
                        )
                        
                        # v17.6: If WPScan says it's not WordPress, downgrade confidence
                        if not wp_actually_detected and wp_res:
                            debug_print(f"    [⚠] WPScan did not confirm WordPress - downgrading detection confidence")
                            host_model.web_context.cms_detected = f"WordPress (Uncertain - detection not confirmed by WPScan)"
                            host_model.web_context.cms_confidence = 0.3  # Very low confidence
                        
                        for wf in wp_res:
                            global_findings.append(Finding(
                                title=f"{wf.get('issue', wf.get('type', 'WP Finding'))} ({ip})", 
                                category="CMS", severity=wf.get('severity', Severity.MEDIUM),
                                description=wf.get('description', wf.get('message', '')), 
                                recommendation=wf.get('recommendation', 'Review WordPress security'),
                                confidence_score=0.9 if wp_actually_detected else 0.4,
                                evidence_type=EvidenceType.VULNERABILITY,
                                raw_output=wf.get('message', '')  # v16.2: Store evidence
                            ))
                        debug_print(f"      ✓ WPScan completed: {len(wp_res)} findings (enumerated plugins/themes/users)")
                    else:
                        debug_print(f"      ⚠ WPScan returned no results - WordPress detection may be incorrect")
                        # v17.6: If WPScan finds nothing, downgrade confidence
                        wp_confidence = getattr(host_model.web_context, 'cms_confidence', 0.7)
                        host_model.web_context.cms_confidence = max(0.3, wp_confidence - 0.3)
                        host_model.web_context.cms_detected = f"WordPress (Uncertain - WPScan found nothing)"
                        debug_print(f"    [⚠] WordPress detection confidence reduced to {host_model.web_context.cms_confidence:.0%}")
                    scan_state[ip]["tools"].append("wpscan")
                elif t_name == "sslscan" and host_model.web_context:
                    host_model.ssl_info = self.sslscan.run(host_model.web_context.url)

                scan_state[ip]["tools"].append(t_name)

            iteration += 1

        global_findings.extend(DecisionEngine.analyze(host_model, None))
        return host_model

    def run(self, input_target: str) -> ScanResult:
        scan_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now().isoformat()
        
        # Color definitions for CLI
        B, C, W = "\033[1;34m", "\033[1;36m", "\033[0m"
        
        print(f"\n{C}{'='*60}{W}")
        print(f" {C}[Phase 1] MEOWWARE RECON & TARGET CONSOLIDATION{W}")
        target_obj = Target(input_target)
        # 1. Target Consolidation
        targets = []
        target_map: Dict[str, Host] = {}
        cloudflare_skipped = []  # v17.3: Agrupar mensajes de Cloudflare

        def add_canonical_target(ip: str, hostname: str, role: str):
            # v16.2: Skip Cloudflare IPs immediately
            # v17.3: Agrupar mensajes de Cloudflare para reducir verbosidad
            if self.cloudflare_filter.is_cloudflare_ip(ip):
                cloudflare_skipped.append(f"{ip} ({hostname})")
                return
            
            is_int = False
            try:
                is_int = ipaddress.ip_address(ip).is_private
            except: pass
            
            if ip not in target_map:
                target_map[ip] = Host(ip=ip, hostname=hostname, aliases=[hostname], roles=[role], is_internal=is_int)
            else:
                h = target_map[ip]
                if hostname not in h.aliases: h.aliases.append(hostname)
                if role not in h.roles: h.roles.append(role)
                h.is_internal = is_int # Update/confirm

        if target_obj.type == 'ip':
            add_canonical_target(input_target, input_target, "Main")
        else:
            for ip in target_obj.resolved_ips: add_canonical_target(ip, target_obj.input_str, "Main")
            root_ip = target_obj.resolved_ips[0] if target_obj.resolved_ips else ""
            if root_ip and self._is_waf(root_ip):
                for m_host, m_ip in self._resolve_mx(target_obj.input_str):
                    if m_ip != root_ip and not self._is_waf(m_ip):
                        add_canonical_target(m_ip, m_host, "Potential Origin (MX)")

            recon_res = self.subdomains.run(target_obj.input_str)
            active_subs = recon_res.get("active", [])
            failed_subs = recon_res.get("failed", [])
            
            for sub in active_subs:
                try: add_canonical_target(socket.gethostbyname(sub), sub, "Subdomain")
                except: pass
            
            # v18.0: Cloud Asset Discovery
            cloud_findings = self.cloud_auditor.run(target_obj.input_str)
            for f in cloud_findings:
                all_findings.append(f)
                debug_print(f"  [Cloud Discovery] Found: {f.title}")

        consolidated_hosts = list(target_map.values())
        
        # v17.3: Mostrar resumen de Cloudflare filtrados
        if cloudflare_skipped:
            if len(cloudflare_skipped) <= 5:
                for cf in cloudflare_skipped:
                    debug_print(f"  [Cloudflare Filter] Skipping Cloudflare IP: {cf}")
            else:
                debug_print(f"  [Cloudflare Filter] Skipping {len(cloudflare_skipped)} Cloudflare IPs (edge nodes)")
                for cf in cloudflare_skipped[:3]:
                    debug_print(f"    - {cf}")
                debug_print(f"    ... and {len(cloudflare_skipped) - 3} more")
        
        # Initialize lists BEFORE using them
        all_hosts_results = []
        all_findings = []
        all_reasoning = []
        
        # v16.2: Double-check filter (should already be filtered, but ensure)
        consolidated_hosts, cloudflare_hosts = self.cloudflare_filter.filter_cloudflare_hosts(consolidated_hosts)
        if cloudflare_hosts:
            debug_print(f"  [Cloudflare Filter] Removed {len(cloudflare_hosts)} Cloudflare edge IP(s) from audit")
            # Add info finding about Cloudflare protection
            for cf_host in cloudflare_hosts:
                if hasattr(cf_host, 'hostname') and cf_host.hostname:
                    all_findings.append(Finding(
                        title=f"Cloudflare Edge Node ({cf_host.hostname})",
                        category="Infrastructure",
                        severity=Severity.INFO,
                        description=f"Host {cf_host.hostname} ({cf_host.ip}) is behind Cloudflare edge network. Origin IP not directly accessible.",
                        recommendation="Cloudflare provides DDoS protection and WAF. Audit origin server directly if accessible."
                    ))
        
        scan_state: Dict[str, Dict[str, Any]] = { h.ip: {"tools": [], "findings": [], "roles": h.roles, "host_obj": h} for h in consolidated_hosts }

        # v12.5: Shared Fingerprint Registry for Tool Dedup (Phase 6 Bonus)
        # Tracks which tools have already run on which backend fingerprint
        fingerprint_registry = {} 

        # --- PHASE 2: CONCURRENT SCANNING [v12.0 ThreadPool] ---
        print(f"\n{C}{'='*60}{W}")
        print(f" {C}[Phase 2/3] PARALLEL AUDIT & VERIFICATION{W}")
        print(f"{C}{'='*60}{W}")
        
        # Phase 4 (DNS) - Run early for domains - with cache
        if target_obj.type == 'domain':
            cached_dns = self.cache.get("dns", target_obj.input_str)
            if cached_dns:
                debug_print(f"  [Cache] Using cached DNS results")
                dns_res = cached_dns
            else:
                dns_res = self.dns_scanner.run(target_obj.input_str)
                self.cache.set("dns", target_obj.input_str, dns_res)
            
            dns_findings = dns_res.get('findings', [])
            for f in dns_findings:
                # v16.2: STRICT VERIFICATION - Only add AXFR findings with CONFIRMED evidence
                # Requirements: NS server identified + complete zone transfer + evidence
                if "AXFR" in f.get('issue', ''):
                    # Verify evidence exists and NS server is identified in description
                    has_evidence = bool(f.get('evidence', '').strip())
                    desc = f.get('description', '')
                    has_ns_identified = any(marker in desc for marker in ['NS server', 'from NS:', 'from NS server'])
                    has_records_confirmed = 'records received' in desc or 'records' in desc.lower()
                    
                    if not (has_evidence and has_ns_identified and has_records_confirmed):
                        debug_print(f"  [Discard] AXFR finding without confirmed evidence - DISCARDED")
                        debug_print(f"    Reason: Evidence={has_evidence}, NS={has_ns_identified}, Records={has_records_confirmed}")
                        continue
                    else:
                        debug_print(f"  [✓] AXFR confirmed with evidence - adding to report")
                
                all_findings.append(Finding(
                    title=f.get('issue', 'DNS Finding'), category="DNS", 
                    severity=f.get('severity', Severity.MEDIUM), 
                    description=f.get('description', ''), 
                    recommendation=f.get('recommendation', ''),
                    raw_output=f.get('evidence', '')  # v16.2: Include evidence for AXFR
                ))
            
            # v16.0: Threat Intelligence Check
            debug_print(f"  [Threat Intel] Checking {target_obj.input_str} against threat feeds...")
            threat_result = self.threat_intel.check_malicious(target_obj.input_str, "domain")
            if threat_result.get("malicious"):
                all_findings.append(Finding(
                    title=f"Threat Intelligence Alert: {target_obj.input_str}",
                    category="Threat Intelligence",
                    severity=Severity.HIGH,
                    description=f"Target found in threat intelligence databases: {', '.join(threat_result['sources'])}. "
                              f"Reputation score: {threat_result['reputation_score']}/100",
                    recommendation="Review threat intelligence details before proceeding",
                    confidence_score=0.9,
                    evidence_type=EvidenceType.HEURISTIC
                ))
                debug_print(f"    ⚠️ Threat detected: {', '.join(threat_result['sources'])}")

        # v16.2: Final Cloudflare filter before audit
        consolidated_hosts = [h for h in consolidated_hosts if not self.cloudflare_filter.is_cloudflare_ip(h.ip)]
        if len(consolidated_hosts) == 0:
            debug_print("  [Cloudflare Filter] All hosts are Cloudflare edge nodes - no origin servers to audit")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Pass fingerprint_registry to _audit_host (needs method signature update)
            future_to_host = {executor.submit(self._audit_host, host, scan_state, all_findings, all_reasoning, fingerprint_registry): host for host in consolidated_hosts[:5]}
            for future in concurrent.futures.as_completed(future_to_host):
                try: 
                    res_host = future.result()
                    all_hosts_results.append(res_host)
                except Exception as exc:
                    # v17.6: Centralized error handling - never contaminate metrics
                    from ..core.error_handler import ErrorHandler, ErrorSeverity
                    
                    # Try to get host IP from future
                    host_ip = "unknown"
                    try:
                        for h in consolidated_hosts:
                            if any(future == f for f in future_to_host.keys()):
                                host_ip = h.ip
                                break
                    except:
                        pass
                    
                    # Handle error internally - never add to findings
                    ErrorHandler.handle_error(
                        exc,
                        context=f"Host audit: {host_ip}",
                        severity=ErrorSeverity.INTERNAL,  # Internal - never expose
                        module="orchestrator._audit_host"
                    )
                    # Error is logged internally but never added to findings

        debug_section("GLOBAL ANALYTICS & RISK SCORING")
        dns_info = None
        if target_obj.type == 'domain':
            try:
                dns_info = Normalizer.parse_domain_info(self.whois.run(target_obj.input_str), self.dig.run(target_obj.input_str))
                all_findings.extend(DecisionEngine.analyze_dns(dns_info))
            except: pass

        for f in all_findings:
            if f.severity in [Severity.HIGH, Severity.CRITICAL]:
                ai_analysis = self.brain.analyze_finding(f.description, f.title)
                f.description += f"\n\n[ANÁLISIS AI]: {ai_analysis}"
            
            # v14.1: Proxy Node Branding
            for h in all_hosts_results:
                if f"({h.ip})" in f.title and h.is_proxy:
                    waf_name = h.web_context.waf_name if h.web_context else 'WAF'
                    f.description += f"\n\n[🛡️ ALERTA NODO PROXY]: Este host está identificado como un nodo {waf_name}. Las vulnerabilidades pueden estar mitigadas o ser genéricas."

        # v14.0: Infrastructure Mapping Post-Process
        infra_summary = {}
        for host in all_hosts_results:
            meta = self.infra_mapper.run(host.ip)
            host.asn = meta.get('asn', '')
            host.geo_location = meta.get('geo', '')
            if target_obj.type == 'domain' and 'dns_res' in locals():
                host.ttl_map = dns_res.get('ttl_map', {})
            infra_summary[host.ip] = meta

        # v16.2: Apply business risk prioritization before creating result
        enhanced_findings = RecommendationEngine.enhance_findings(all_findings)
        prioritized_findings = self.business_risk.prioritize_findings(enhanced_findings, all_hosts_results)
        
        # v17.6: Validate findings - ensure CRITICAL findings have evidence
        from ..core.finding_validator import FindingValidator
        validated_findings = []
        for finding in prioritized_findings:
            try:
                validated = FindingValidator.validate_finding(finding)
                # Check if CRITICAL has sufficient evidence
                if validated.severity == Severity.CRITICAL:
                    if not FindingValidator.has_sufficient_evidence(validated):
                        debug_print(f"  [Validator] Downgrading CRITICAL finding '{validated.title}' - insufficient evidence")
                        validated.severity = Severity.HIGH
                        validated.confidence_score = min(validated.confidence_score, 0.75)
                        validated.description += "\n\n[NOTE: Severity downgraded from CRITICAL to HIGH due to insufficient evidence]"
                validated_findings.append(validated)
            except Exception as e:
                debug_print(f"  [⚠] Error validating finding '{finding.title}': {e}")
                validated_findings.append(finding)  # Keep original if validation fails
        
        # v17.4: Deduplicate findings before creating final result
        from ..intelligence.finding_deduplicator import FindingDeduplicator
        deduplicator = FindingDeduplicator()
        prioritized_findings = deduplicator.consolidate_findings(validated_findings)
        debug_print(f"  [Deduplicator] Final findings after deduplication: {len(prioritized_findings)}")
        
        # v17.6: Fix host counting - ensure all_hosts_results matches actual audited hosts
        # Filter out hosts that were skipped or failed
        audited_hosts = [h for h in all_hosts_results if h.services or h.web_context]
        debug_print(f"  [Host Count] Audited hosts: {len(audited_hosts)} (from {len(all_hosts_results)} total)")
        
        result = ScanResult(
            id=scan_id, timestamp=timestamp, target=ScanTarget(input=target_obj.input_str, type=target_obj.type, resolved_ips=target_obj.resolved_ips),
            hosts=audited_hosts, dns=dns_info, findings=prioritized_findings, 
            ai_reasoning=all_reasoning, failed_subdomains=failed_subs, infrastructure_map=infra_summary
        )
        
        # v14.0 Save & Diff
        history_diff = self.history.get_diff(result)
        if history_diff:
            result.findings.append(Finding(
                title="Infrastructure Variation Detected", category="History", severity=Severity.INFO,
                description="Infrastructure changes detected since last audit:\n" + "\n".join(history_diff),
                recommendation="Review if these changes (e.g. retired subdomains) were intentional."
            ))
        self.history.save_scan(result)
        
        # v16.2: Save to database and filter false positives
        scan_start_time = datetime.datetime.fromisoformat(timestamp)
        scan_duration = int((datetime.datetime.now() - scan_start_time).total_seconds())
        self.scan_db.save_scan(result, scan_duration)
        
        # Filter known false positives using historical context
        original_count = len(result.findings)
        result.findings = self.historical_context.filter_known_false_positives(result.findings, target_obj.input_str)
        filtered_count = original_count - len(result.findings)
        if filtered_count > 0:
            debug_print(f"  [Historical Context] Filtered {filtered_count} known false positives")
        
        # v16.0: Learn from this scan
        tech_stack_all = {}
        for host in all_hosts_results:
            if host.web_context and hasattr(host.web_context, 'tech_versions'):
                tech_versions = host.web_context.tech_versions
                # v16.1: Ensure tech_versions is a dict before updating
                if isinstance(tech_versions, dict):
                    tech_stack_all.update(tech_versions)
        
        tools_used = []
        for host in all_hosts_results:
            if host.ip in scan_state:
                tools_used.extend(scan_state[host.ip].get("tools", []))
        
        if tools_used:
            self.pattern_learner.learn_from_scan(result, list(set(tools_used)), scan_duration, tech_stack_all)
            debug_print(f"  [Pattern Learning] Learned from scan: {len(set(tools_used))} tools, {scan_duration}s duration")
        
        # v16.0: Print cache stats
        cache_stats = self.cache.get_stats()
        if cache_stats["total_entries"] > 0:
            debug_print(f"  [Cache] Stats: {cache_stats['total_entries']} entries, {cache_stats['total_size_mb']} MB")
        
        # v17.0: Generate Executive Report
        try:
            debug_print(f"\n  [Report] Generating executive report...")
            executive_report = self.executive_reporter.generate_executive_report(result)
            
            # Save executive report to file
            import os
            report_dir = "reports"
            os.makedirs(report_dir, exist_ok=True)
            report_file = os.path.join(report_dir, f"executive_report_{scan_id}.html")
            
            html_report = self.executive_reporter.generate_html_report(executive_report)
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            debug_print(f"  [Report] Report saved to: {report_file}")
            
            # v1.0: Generate Interactive Dashboard
            debug_print(f"  [Report] Generating interactive dashboard...")
            dashboard_html = self.dashboard_reporter.generate_dashboard(result)
            dashboard_file = os.path.join(report_dir, f"dashboard_{scan_id}.html")
            with open(dashboard_file, 'w', encoding='utf-8') as f:
                f.write(dashboard_html)
            debug_print(f"  [Report] Dashboard saved to: {dashboard_file}")
            
            debug_print(f"  ✓ Reports generated successfully")
            
            # Also save JSON version
            import json
            json_file = os.path.join(report_dir, f"executive_report_{scan_id}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(executive_report, f, indent=2, default=str)
            
            # Store report in result
            if not hasattr(result, 'executive_report'):
                result.executive_report = executive_report
            
        except Exception as e:
            debug_print(f"  ⚠️  Executive report generation failed: {e}")
        
        return result
    
    def _validate_nuclei_tags(self, tags: str, host: Host) -> str:
        """
        v17.1: Valida y filtra tags de nuclei según tech stack real detectado.
        Remueve tags irrelevantes y agrega tags relevantes.
        """
        if not tags:
            tags = "exposure"
        
        # Convertir a lista
        tag_list = [t.strip() for t in tags.split(',') if t.strip()]
        valid_tags = []
        
        # Obtener tech stack real
        tech_stack = getattr(host, 'tech_stack_info', None)
        detected_cms = None
        detected_os = None
        detected_db = None
        detected_web = None
        
        if tech_stack:
            detected_cms = getattr(tech_stack, 'cms', None)
            detected_os = getattr(tech_stack, 'os', None)
            detected_db = getattr(tech_stack, 'database', None)
            detected_web = getattr(tech_stack, 'web_server', None)
        
        # También verificar web_context
        if host.web_context:
            if not detected_cms and host.web_context.cms_detected:
                detected_cms = host.web_context.cms_detected
        
        # Mapeo de tecnologías detectadas a tags relevantes
        relevant_tags = set()
        
        # CMS tags
        if detected_cms:
            cms_lower = str(detected_cms).lower()
            if 'wordpress' in cms_lower:
                relevant_tags.add('wordpress')
            elif 'joomla' in cms_lower:
                relevant_tags.add('joomla')
            elif 'drupal' in cms_lower:
                relevant_tags.add('drupal')
            elif 'magento' in cms_lower:
                relevant_tags.add('magento')
        
        # OS tags
        if detected_os:
            os_str = str(detected_os).lower()
            if 'windows' in os_str:
                relevant_tags.add('windows')
                relevant_tags.add('iis')
            elif 'linux' in os_str:
                relevant_tags.add('linux')
        
        # Database tags
        if detected_db:
            db_lower = str(detected_db).lower()
            if 'mysql' in db_lower:
                relevant_tags.add('mysql')
            elif 'postgres' in db_lower:
                relevant_tags.add('postgres')
            elif 'mongodb' in db_lower:
                relevant_tags.add('mongodb')
            elif 'redis' in db_lower:
                relevant_tags.add('redis')
        
        # Web server tags
        if detected_web:
            web_lower = str(detected_web).lower()
            if 'apache' in web_lower:
                relevant_tags.add('apache')
            elif 'nginx' in web_lower:
                relevant_tags.add('nginx')
            elif 'iis' in web_lower:
                relevant_tags.add('iis')
        
        # Tags siempre relevantes (genéricos)
        always_relevant = {'cve', 'exposure', 'exposed', 'misconfig', 'default-logins'}
        relevant_tags.update(always_relevant)
        
        # Filtrar tags: solo incluir los relevantes
        # v17.4: Safe processing - handle None values
        removed_tags = []
        for tag in tag_list:
            if tag is None:
                continue
            tag_str = str(tag).strip()
            if not tag_str:
                continue
            tag_lower = tag_str.lower()
            # Incluir si es relevante o si es un tag genérico útil
            if tag_lower in relevant_tags or tag_lower in always_relevant:
                valid_tags.append(tag_lower)
            else:
                removed_tags.append(tag_lower)
        
        # Si no quedaron tags válidos, usar tags básicos
        if not valid_tags:
            valid_tags = ['exposure', 'cve', 'misconfig']
            debug_print(f"    [Tag Validation] No valid tags - using generic tags only")
        else:
            if removed_tags:
                debug_print(f"    [Tag Validation] Removed {len(removed_tags)} irrelevant tags: {', '.join(removed_tags[:5])}")
        
        # Limitar a 10 tags máximo
        final_tags = ','.join(list(set(valid_tags))[:10])
        debug_print(f"    [Tag Validation] Final tags ({len(final_tags.split(','))}): {final_tags}")
        return final_tags
