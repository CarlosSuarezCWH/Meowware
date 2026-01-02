"""
Audit Profiles System
v17.4: Technology-specific audit profiles for intelligent fallback

Meowware - Developed by Carlos Mancera
"""
from typing import Dict, List, Any, Optional
from ..core.models import Host, Service
from ..core.debug import debug_print

class AuditProfile:
    """Defines audit strategy for a specific technology stack"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.tool_sequence = []  # Ordered list of tools to execute
        self.priority_tools = []  # High priority tools
        self.conditional_tools = {}  # Tools based on findings
        self.stop_conditions = []  # When to stop auditing
    
    def get_next_tool(self, executed_tools: List[str], findings: List[Any], 
                     services: List[Service]) -> Optional[str]:
        """Get next tool to execute based on profile"""
        # Check priority tools first
        for tool in self.priority_tools:
            if tool not in executed_tools:
                return tool
        
        # Check tool sequence
        for tool in self.tool_sequence:
            if tool not in executed_tools:
                # Check conditional requirements
                if tool in self.conditional_tools:
                    condition = self.conditional_tools[tool]
                    if not self._check_condition(condition, findings, services):
                        continue
                return tool
        
        return None
    
    def _check_condition(self, condition: Dict[str, Any], findings: List[Any], 
                        services: List[Service]) -> bool:
        """Check if condition is met for conditional tool"""
        # Simple condition checking
        if "requires_port" in condition:
            port = condition["requires_port"]
            if not any(s.port == port and s.state == 'open' for s in services):
                return False
        
        if "requires_finding" in condition:
            finding_type = condition["requires_finding"]
            if not any(f.title.lower().contains(finding_type.lower()) for f in findings):
                return False
        
        return True

class AuditProfileManager:
    """Manages audit profiles for different technology stacks"""
    
    def __init__(self):
        self.profiles = self._initialize_profiles()
    
    def _initialize_profiles(self) -> Dict[str, AuditProfile]:
        """Initialize predefined audit profiles"""
        profiles = {}
        
        # WordPress Profile
        wp_profile = AuditProfile("WordPress", "WordPress CMS audit profile")
        wp_profile.priority_tools = ["wpscan", "nuclei:tags=wordpress,cve"]
        wp_profile.tool_sequence = [
            "testssl", "sslscan",  # SSL/TLS first
            "dirsearch",  # Directory enumeration
            "feroxbuster",  # Web fuzzing
            "git-dumper",  # Source code exposure
            "security-headers",  # Security headers
            "nuclei:tags=wordpress,exposure",  # WordPress-specific
        ]
        wp_profile.conditional_tools = {
            "sqlmap": {"requires_finding": "sql injection"},
            "subjack": {"requires_finding": "subdomain"}
        }
        profiles["wordpress"] = wp_profile
        
        # Linux Web Server Profile
        linux_web_profile = AuditProfile("Linux Web Server", "Linux with web services")
        linux_web_profile.priority_tools = ["nuclei:tags=linux,apache,nginx,cve"]
        linux_web_profile.tool_sequence = [
            "ssh_scanner",  # SSH security
            "testssl", "sslscan",  # SSL/TLS
            "nikto",  # Web server scanner
            "dirsearch",  # Directory enumeration
            "nuclei:tags=exposure,cve,misconfig",  # Generic vulnerabilities
        ]
        profiles["linux_web"] = linux_web_profile
        
        # Windows Server Profile
        windows_profile = AuditProfile("Windows Server", "Windows server audit profile")
        windows_profile.priority_tools = ["rdp_scanner", "smb_scanner", "nuclei:tags=windows,iis,cve"]
        windows_profile.tool_sequence = [
            "rdp_scanner",  # RDP vulnerabilities
            "smb_scanner",  # SMB vulnerabilities
            "nuclei:tags=windows,iis",  # Windows/IIS CVEs
            "nuclei:tags=mssql,exposure",  # MSSQL if detected
        ]
        profiles["windows"] = windows_profile
        
        # Mail Server Profile
        mail_profile = AuditProfile("Mail Server", "Mail server audit profile")
        mail_profile.priority_tools = ["smtp-user-enum", "nuclei:tags=smtp,imap,pop3"]
        mail_profile.tool_sequence = [
            "smtp-user-enum",  # SMTP user enumeration
            "nuclei:tags=smtp,exposure",  # SMTP vulnerabilities
            "nuclei:tags=imap,pop3",  # IMAP/POP3 vulnerabilities
            "testssl",  # SSL/TLS for mail services
        ]
        profiles["mail"] = mail_profile
        
        # Database Server Profile
        db_profile = AuditProfile("Database Server", "Database server audit profile")
        db_profile.priority_tools = ["mysql-client", "nuclei:tags=mysql,postgres,mongodb,redis,exposure"]
        db_profile.tool_sequence = [
            "mysql-client",  # MySQL check (if MySQL)
            "nuclei:tags=mysql,exposure",  # MySQL vulnerabilities
            "nuclei:tags=postgres,exposure",  # PostgreSQL vulnerabilities
            "nuclei:tags=mongodb,exposure",  # MongoDB vulnerabilities
            "nuclei:tags=redis,exposure",  # Redis vulnerabilities
        ]
        profiles["database"] = db_profile
        
        # Generic/Unknown Profile
        generic_profile = AuditProfile("Generic", "Generic audit profile for unknown stacks")
        generic_profile.priority_tools = ["nuclei:tags=exposure,cve,misconfig"]
        generic_profile.tool_sequence = [
            "nuclei:tags=exposure,cve,misconfig,default-logins",  # Generic scan
            "testssl",  # SSL/TLS if HTTPS
            "nikto",  # Web server scanner if web service
        ]
        profiles["generic"] = generic_profile
        
        return profiles
    
    def get_profile(self, tech_stack: Dict[str, Any], host: Host) -> AuditProfile:
        """Get appropriate audit profile based on technology stack"""
        # Check CMS first
        cms = tech_stack.get('cms', '').lower() if tech_stack else ''
        if 'wordpress' in cms:
            return self.profiles["wordpress"]
        elif 'joomla' in cms:
            # Similar to WordPress but with joomscan
            profile = AuditProfile("Joomla", "Joomla CMS audit profile")
            profile.priority_tools = ["joomscan", "nuclei:tags=joomla,cve"]
            profile.tool_sequence = ["joomscan", "nuclei:tags=joomla", "testssl", "dirsearch"]
            return profile
        elif 'drupal' in cms:
            profile = AuditProfile("Drupal", "Drupal CMS audit profile")
            profile.priority_tools = ["droopescan", "nuclei:tags=drupal,cve"]
            profile.tool_sequence = ["droopescan", "nuclei:tags=drupal", "testssl", "dirsearch"]
            return profile
        
        # Check OS
        os_info = tech_stack.get('os', '') if tech_stack else ''
        if hasattr(os_info, 'value'):
            os_info = os_info.value
        
        if 'windows' in str(os_info).lower():
            return self.profiles["windows"]
        
        # Check for mail server
        hostname_lower = (host.hostname or '').lower()
        if 'mail' in hostname_lower or 'smtp' in hostname_lower:
            smtp_ports = [s.port for s in host.services if s.port in [25, 587, 465] and s.state == 'open']
            if smtp_ports:
                return self.profiles["mail"]
        
        # Check for database server
        db_ports = [s.port for s in host.services if s.port in [3306, 5432, 27017, 6379] and s.state == 'open']
        if db_ports:
            return self.profiles["database"]
        
        # Check for web server
        web_ports = [s.port for s in host.services if s.port in [80, 443, 8080, 8443] and s.state == 'open']
        if web_ports:
            if 'linux' in str(os_info).lower():
                return self.profiles["linux_web"]
        
        # Default to generic
        return self.profiles["generic"]
    
    def get_intelligent_fallback(self, host: Host, tech_stack: Dict[str, Any], 
                                executed_tools: List[str], findings: List[Any]) -> Optional[str]:
        """Get intelligent fallback tool based on audit profile"""
        profile = self.get_profile(tech_stack, host)
        debug_print(f"    [Profile] Using {profile.name} profile: {profile.description}")
        
        next_tool = profile.get_next_tool(executed_tools, findings, host.services)
        if next_tool:
            debug_print(f"    [Profile] Next tool: {next_tool}")
            return next_tool
        
        debug_print(f"    [Profile] No more tools in {profile.name} profile")
        return None

