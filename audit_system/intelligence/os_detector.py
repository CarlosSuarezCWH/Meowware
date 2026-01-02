"""
OS Detection and Technology Stack Analyzer
Detects operating system and technology stack to adapt audit flow

Meowware v16.4 - Developed by Carlos Mancera
"""
from typing import List, Dict, Any, Optional
from ..core.models import Host, Service
from ..core.debug import debug_print
from enum import Enum

class OperatingSystem(str, Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    BSD = "BSD"
    UNIX = "Unix"
    ANDROID = "Android"
    IOS = "iOS"
    UNKNOWN = "Unknown"

class TechnologyStack:
    """
    Represents detected technology stack
    """
    def __init__(self):
        self.os: OperatingSystem = OperatingSystem.UNKNOWN
        self.web_server: Optional[str] = None
        self.database: Optional[str] = None
        self.cms: Optional[str] = None
        self.programming_language: Optional[str] = None
        self.frameworks: List[str] = []
        self.confidence: float = 0.0
    
    def __str__(self) -> str:
        parts = [f"OS: {self.os.value}"]
        if self.web_server:
            parts.append(f"Web: {self.web_server}")
        if self.database:
            parts.append(f"DB: {self.database}")
        if self.cms:
            parts.append(f"CMS: {self.cms}")
        if self.programming_language:
            parts.append(f"Lang: {self.programming_language}")
        if self.frameworks:
            parts.append(f"Frameworks: {', '.join(self.frameworks)}")
        return " | ".join(parts) if parts else "Unknown"

class OSDetector:
    """
    Detects operating system and technology stack from services and banners
    """
    
    # Windows indicators
    WINDOWS_INDICATORS = {
        "ports": [3389, 445, 139, 135, 1433],  # RDP, SMB, NetBIOS, RPC, MSSQL
        "services": ["microsoft-ds", "ms-sql-s", "rdp", "netbios"],
        "banners": ["windows", "microsoft", "iis", "mssql", "smb"]
    }
    
    # Linux indicators
    LINUX_INDICATORS = {
        "ports": [22, 3306, 5432, 6379, 27017, 9200, 5601, 8080, 3000, 5000],  # SSH, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kibana, Node.js, Flask, etc.
        "services": ["ssh", "mysql", "postgresql", "redis", "mongodb", "elasticsearch", "kibana", "http", "https"],
        "banners": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora", "suse", "apache", "nginx", "mysql", "postgresql"]
    }
    
    # macOS indicators
    MACOS_INDICATORS = {
        "ports": [22, 548, 631],  # SSH, AFP, CUPS
        "services": ["ssh", "afp", "cups"],
        "banners": ["macos", "darwin", "apple"]
    }
    
    # BSD indicators
    BSD_INDICATORS = {
        "ports": [22, 514],
        "services": ["ssh", "syslog"],
        "banners": ["freebsd", "openbsd", "netbsd", "bsd"]
    }
    
    def detect_os_and_stack(self, host: Host) -> TechnologyStack:
        """
        Detect OS and technology stack from host services and context
        """
        stack = TechnologyStack()
        
        # Analyze services
        os_scores = {
            OperatingSystem.WINDOWS: 0,
            OperatingSystem.LINUX: 0,
            OperatingSystem.MACOS: 0,
            OperatingSystem.BSD: 0
        }
        
        for service in host.services:
            if service.state != 'open':
                continue
            
            banner_lower = (service.banner or service.product or "").lower()
            service_name_lower = service.name.lower()
            
            # Port-based detection
            if service.port in self.WINDOWS_INDICATORS["ports"]:
                os_scores[OperatingSystem.WINDOWS] += 2
            if service.port in self.LINUX_INDICATORS["ports"]:
                os_scores[OperatingSystem.LINUX] += 2
            if service.port in self.MACOS_INDICATORS["ports"]:
                os_scores[OperatingSystem.MACOS] += 2
            if service.port in self.BSD_INDICATORS["ports"]:
                os_scores[OperatingSystem.BSD] += 2
            
            # Service name detection
            if any(ind in service_name_lower for ind in self.WINDOWS_INDICATORS["services"]):
                os_scores[OperatingSystem.WINDOWS] += 1
            if any(ind in service_name_lower for ind in self.LINUX_INDICATORS["services"]):
                os_scores[OperatingSystem.LINUX] += 1
            if any(ind in service_name_lower for ind in self.MACOS_INDICATORS["services"]):
                os_scores[OperatingSystem.MACOS] += 1
            if any(ind in service_name_lower for ind in self.BSD_INDICATORS["services"]):
                os_scores[OperatingSystem.BSD] += 1
            
            # Banner detection
            if any(ind in banner_lower for ind in self.WINDOWS_INDICATORS["banners"]):
                os_scores[OperatingSystem.WINDOWS] += 2
            if any(ind in banner_lower for ind in self.LINUX_INDICATORS["banners"]):
                os_scores[OperatingSystem.LINUX] += 2
            if any(ind in banner_lower for ind in self.MACOS_INDICATORS["banners"]):
                os_scores[OperatingSystem.MACOS] += 2
            if any(ind in banner_lower for ind in self.BSD_INDICATORS["banners"]):
                os_scores[OperatingSystem.BSD] += 2
            
            # Specific service detection
            if service.port == 3389:  # RDP
                os_scores[OperatingSystem.WINDOWS] += 5
                stack.os = OperatingSystem.WINDOWS
            elif service.port == 445:  # SMB
                os_scores[OperatingSystem.WINDOWS] += 3
            elif service.port == 1433:  # MSSQL
                os_scores[OperatingSystem.WINDOWS] += 3
                stack.database = "MSSQL"
            elif service.port == 3306:  # MySQL
                os_scores[OperatingSystem.LINUX] += 1
                stack.database = "MySQL"
            elif service.port == 5432:  # PostgreSQL
                os_scores[OperatingSystem.LINUX] += 1
                stack.database = "PostgreSQL"
            elif service.port == 27017:  # MongoDB
                os_scores[OperatingSystem.LINUX] += 1
                stack.database = "MongoDB"
            elif service.port == 6379:  # Redis
                os_scores[OperatingSystem.LINUX] += 1
                stack.database = "Redis"
            elif service.port == 9200:  # Elasticsearch
                os_scores[OperatingSystem.LINUX] += 1
                stack.database = "Elasticsearch"
            elif service.port == 548:  # AFP (macOS)
                os_scores[OperatingSystem.MACOS] += 3
            elif service.port == 631:  # CUPS (macOS)
                os_scores[OperatingSystem.MACOS] += 2
        
        # Web context analysis
        if host.web_context:
            # Web server detection
            tech_stack = host.web_context.tech_stack or []
            tech_versions = getattr(host.web_context, 'tech_versions', {}) or {}
            
            if "IIS" in str(tech_stack) or "iis" in str(tech_versions).lower():
                os_scores[OperatingSystem.WINDOWS] += 3
                stack.web_server = "IIS"
            elif "Apache" in str(tech_stack) or "apache" in str(tech_versions).lower():
                os_scores[OperatingSystem.LINUX] += 2
                stack.web_server = "Apache"
            elif "Nginx" in str(tech_stack) or "nginx" in str(tech_versions).lower():
                os_scores[OperatingSystem.LINUX] += 2
                stack.web_server = "Nginx"
            
            # CMS detection
            if host.web_context.cms_detected:
                stack.cms = host.web_context.cms_detected
                if stack.cms.lower() == "wordpress":
                    os_scores[OperatingSystem.LINUX] += 1  # WordPress typically runs on Linux
            
            # Programming language detection
            if "PHP" in str(tech_stack) or "php" in str(tech_versions).lower():
                stack.programming_language = "PHP"
                os_scores[OperatingSystem.LINUX] += 1
            elif "ASP.NET" in str(tech_stack) or "asp" in str(tech_stack).lower():
                stack.programming_language = "ASP.NET"
                os_scores[OperatingSystem.WINDOWS] += 2
            elif "Python" in str(tech_stack) or "python" in str(tech_stack).lower():
                stack.programming_language = "Python"
                os_scores[OperatingSystem.LINUX] += 1
            elif "Node.js" in str(tech_stack) or "node" in str(tech_stack).lower() or "express" in str(tech_stack).lower():
                stack.programming_language = "Node.js"
                os_scores[OperatingSystem.LINUX] += 1
            elif "Ruby" in str(tech_stack) or "ruby" in str(tech_stack).lower() or "rails" in str(tech_stack).lower():
                stack.programming_language = "Ruby"
                os_scores[OperatingSystem.LINUX] += 1
            elif "Java" in str(tech_stack) or "java" in str(tech_stack).lower() or "spring" in str(tech_stack).lower():
                stack.programming_language = "Java"
                os_scores[OperatingSystem.LINUX] += 1
            elif "Go" in str(tech_stack) or "golang" in str(tech_stack).lower():
                stack.programming_language = "Go"
                os_scores[OperatingSystem.LINUX] += 1
            elif "Rust" in str(tech_stack) or "rust" in str(tech_stack).lower():
                stack.programming_language = "Rust"
                os_scores[OperatingSystem.LINUX] += 1
            
            # Framework detection
            tech_stack_str = str(tech_stack).lower()
            if "laravel" in tech_stack_str:
                stack.frameworks.append("Laravel")
            elif "django" in tech_stack_str:
                stack.frameworks.append("Django")
            elif "rails" in tech_stack_str or "ruby on rails" in tech_stack_str:
                stack.frameworks.append("Ruby on Rails")
            elif "spring" in tech_stack_str:
                stack.frameworks.append("Spring")
            elif "express" in tech_stack_str:
                stack.frameworks.append("Express.js")
            elif "flask" in tech_stack_str:
                stack.frameworks.append("Flask")
            elif "symfony" in tech_stack_str:
                stack.frameworks.append("Symfony")
            elif "asp.net" in tech_stack_str or "aspnet" in tech_stack_str:
                stack.frameworks.append("ASP.NET")
            elif "react" in tech_stack_str:
                stack.frameworks.append("React")
            elif "angular" in tech_stack_str:
                stack.frameworks.append("Angular")
            elif "vue" in tech_stack_str:
                stack.frameworks.append("Vue.js")
            
            # CMS detection (expanded)
            if host.web_context.cms_detected:
                stack.cms = host.web_context.cms_detected
                cms_lower = stack.cms.lower()
                if cms_lower in ["wordpress", "joomla", "drupal"]:
                    os_scores[OperatingSystem.LINUX] += 1
                elif cms_lower in ["magento", "prestashop", "opencart"]:
                    os_scores[OperatingSystem.LINUX] += 1
                elif cms_lower in ["moodle", "drupal"]:
                    os_scores[OperatingSystem.LINUX] += 1
        
        # Determine OS
        max_os = max(os_scores, key=os_scores.get)
        max_score = os_scores[max_os]
        
        if max_score >= 3:
            stack.os = max_os
            stack.confidence = min(0.9, max_score / 10.0)
        else:
            stack.os = OperatingSystem.UNKNOWN
            stack.confidence = 0.5
        
        debug_print(f"    [OS Detector] Detected: {stack}")
        return stack
    
    def get_audit_priorities(self, stack: TechnologyStack) -> Dict[str, Any]:
        """
        Get audit priorities based on detected technology stack
        """
        priorities = {
            "high_priority_tools": [],
            "medium_priority_tools": [],
            "low_priority_tools": [],
            "reasoning": []
        }
        
        # Windows-specific priorities
        if stack.os == OperatingSystem.WINDOWS:
            priorities["high_priority_tools"].extend([
                "rdp_scanner",  # RDP vulnerabilities
                "smb_scanner",  # SMB vulnerabilities
                "nuclei:tags=iis,windows",  # Windows/IIS CVEs
            ])
            priorities["reasoning"].append("Windows detected: Prioritizing RDP, SMB, and IIS security checks")
            
            if stack.database == "MSSQL":
                priorities["high_priority_tools"].append("nuclei:tags=mssql,exposure")
                priorities["reasoning"].append("MSSQL detected: Checking for exposed database")
        
        # Linux-specific priorities
        elif stack.os == OperatingSystem.LINUX:
            priorities["high_priority_tools"].extend([
                "ssh_scanner",  # SSH vulnerabilities
                "nuclei:tags=linux,apache,nginx",  # Linux web server CVEs
            ])
            priorities["reasoning"].append("Linux detected: Prioritizing SSH and web server security checks")
            
            if stack.database:
                priorities["high_priority_tools"].append(f"nuclei:tags={stack.database.lower()},exposure")
                priorities["reasoning"].append(f"{stack.database} detected: Checking for exposed database")
        
        # CMS-specific priorities
        if stack.cms:
            cms_lower = stack.cms.lower()
            if cms_lower == "wordpress":
                priorities["high_priority_tools"].extend([
                    "wpscan",  # WordPress scanner
                    "nuclei:tags=wordpress,cve",  # WordPress CVEs
                ])
                priorities["reasoning"].append("WordPress detected: Deep CMS audit required")
            elif cms_lower == "joomla":
                priorities["high_priority_tools"].extend([
                    "joomscan",
                    "nuclei:tags=joomla,cve",
                ])
                priorities["reasoning"].append("Joomla detected: Component and configuration audit required")
            elif cms_lower == "drupal":
                priorities["high_priority_tools"].extend([
                    "droopescan",
                    "nuclei:tags=drupal,cve",
                ])
                priorities["reasoning"].append("Drupal detected: Module and configuration audit required")
            elif cms_lower in ["magento", "prestashop", "opencart"]:
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=ecommerce,cve",
                    "nuclei:tags=magento,cve" if cms_lower == "magento" else "nuclei:tags=prestashop,cve",
                ])
                priorities["reasoning"].append(f"{stack.cms} detected: E-commerce platform audit required")
            elif cms_lower == "moodle":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=moodle,cve",
                ])
                priorities["reasoning"].append("Moodle detected: Learning management system audit required")
        
        # Framework-specific priorities
        if stack.frameworks:
            for framework in stack.frameworks:
                framework_lower = framework.lower()
                if "laravel" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=laravel,cve",
                        "api-scanner",  # Laravel often has APIs
                    ])
                    priorities["reasoning"].append("Laravel detected: Framework and API audit required")
                elif "django" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=django,cve",
                        "api-scanner",
                    ])
                    priorities["reasoning"].append("Django detected: Framework and API audit required")
                elif "rails" in framework_lower or "ruby on rails" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=rails,cve",
                        "nuclei:tags=ruby,cve",
                    ])
                    priorities["reasoning"].append("Ruby on Rails detected: Framework audit required")
                elif "spring" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=spring,cve",
                        "nuclei:tags=java,cve",
                    ])
                    priorities["reasoning"].append("Spring detected: Java framework audit required")
                elif "express" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=nodejs,cve",
                        "api-scanner",
                    ])
                    priorities["reasoning"].append("Express.js detected: Node.js framework audit required")
                elif "flask" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=flask,cve",
                        "api-scanner",
                    ])
                    priorities["reasoning"].append("Flask detected: Python framework audit required")
                elif "symfony" in framework_lower:
                    priorities["high_priority_tools"].extend([
                        "nuclei:tags=symfony,cve",
                    ])
                    priorities["reasoning"].append("Symfony detected: PHP framework audit required")
        
        # Web server priorities
        if stack.web_server:
            if stack.web_server == "IIS":
                priorities["high_priority_tools"].append("nuclei:tags=iis,cve")
            elif stack.web_server in ["Apache", "Nginx"]:
                priorities["high_priority_tools"].append(f"nuclei:tags={stack.web_server.lower()},cve")
            elif stack.web_server == "Tomcat":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=tomcat,cve",
                    "nuclei:tags=java,cve",
                ])
        
        # Programming language priorities
        if stack.programming_language:
            lang_lower = stack.programming_language.lower()
            if lang_lower == "php":
                priorities["medium_priority_tools"].append("nuclei:tags=php,cve")
            elif lang_lower == "asp.net" or lang_lower == "aspnet":
                priorities["medium_priority_tools"].append("nuclei:tags=aspnet,cve")
            elif lang_lower == "python":
                priorities["medium_priority_tools"].append("nuclei:tags=python,cve")
            elif lang_lower == "node.js" or lang_lower == "nodejs":
                priorities["medium_priority_tools"].extend([
                    "nuclei:tags=nodejs,cve",
                    "api-scanner",
                ])
            elif lang_lower == "java":
                priorities["medium_priority_tools"].extend([
                    "nuclei:tags=java,cve",
                    "nuclei:tags=spring,cve",
                ])
            elif lang_lower == "ruby":
                priorities["medium_priority_tools"].extend([
                    "nuclei:tags=ruby,cve",
                    "nuclei:tags=rails,cve",
                ])
            elif lang_lower == "go" or lang_lower == "golang":
                priorities["medium_priority_tools"].append("nuclei:tags=golang,cve")
        
        # Database-specific priorities
        if stack.database:
            db_lower = stack.database.lower()
            if db_lower == "mysql":
                priorities["high_priority_tools"].extend([
                    "mysql-client",
                    "nuclei:tags=mysql,exposure",
                ])
            elif db_lower == "postgresql":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=postgres,exposure",
                ])
            elif db_lower == "mongodb":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=mongodb,exposure",
                ])
            elif db_lower == "redis":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=redis,exposure",
                ])
            elif db_lower == "elasticsearch":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=elasticsearch,exposure",
                ])
            elif db_lower == "mssql":
                priorities["high_priority_tools"].extend([
                    "nuclei:tags=mssql,exposure",
                ])
        
        # macOS-specific priorities
        if stack.os == OperatingSystem.MACOS:
            priorities["high_priority_tools"].extend([
                "nuclei:tags=macos,cve",
            ])
            priorities["reasoning"].append("macOS detected: macOS-specific security checks")
        
        # BSD-specific priorities
        if stack.os == OperatingSystem.BSD:
            priorities["high_priority_tools"].extend([
                "nuclei:tags=bsd,cve",
            ])
            priorities["reasoning"].append("BSD detected: BSD-specific security checks")
        
        return priorities

