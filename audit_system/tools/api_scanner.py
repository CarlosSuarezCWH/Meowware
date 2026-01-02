"""
API Scanner
v16.2: Detects and audits REST APIs, GraphQL, WebSockets

Meowware - Developed by Carlos Mancera
"""
import requests
import json
import re
from typing import Dict, Any, List, Optional
from .base import BaseTool
from ..core.debug import debug_print
from ..core.models import Finding, Severity
from ..core.http_pool import get_http_pool

class APIScanner(BaseTool):
    """Scans for APIs and tests common vulnerabilities"""
    
    @property
    def name(self) -> str:
        return "api_scanner"
    
    def run(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Scan for APIs and common API vulnerabilities
        
        Args:
            target_url: Base URL to scan
        
        Returns:
            List of findings
        """
        findings = []
        http_pool = get_http_pool()
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
        
        base_url = target_url.rstrip('/')
        
        debug_print(f"  [API Scanner] Scanning {base_url} for APIs...")
        
        # 1. Detect API endpoints
        api_endpoints = self._discover_api_endpoints(base_url, http_pool)
        
        # 2. Detect GraphQL
        graphql_info = self._detect_graphql(base_url, http_pool)
        
        # 3. Detect WebSockets
        websocket_info = self._detect_websockets(base_url, http_pool)
        
        # 4. Test common API vulnerabilities
        if api_endpoints:
            findings.extend(self._test_api_vulnerabilities(base_url, api_endpoints, http_pool))
        
        if graphql_info:
            findings.extend(self._test_graphql_vulnerabilities(base_url, graphql_info, http_pool))
        
        return findings
    
    def _discover_api_endpoints(self, base_url: str, http_pool) -> List[str]:
        """Discover API endpoints"""
        endpoints = []
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/rest/api',
            '/graphql', '/graphiql', '/playground',
            '/swagger', '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/api-docs', '/docs',
            '/v1', '/v2', '/v3'
        ]
        
        for path in common_paths:
            try:
                url = f"{base_url}{path}"
                response = http_pool.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    endpoints.append(path)
                    debug_print(f"    [API] Found endpoint: {path} (Status: {response.status_code})")
                    
                    # Check for Swagger/OpenAPI
                    if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                        endpoints.append(f"{path}/swagger.json")
            except:
                pass
        
        return endpoints
    
    def _detect_graphql(self, base_url: str, http_pool) -> Optional[Dict[str, Any]]:
        """Detect GraphQL endpoint"""
        graphql_paths = ['/graphql', '/graphiql', '/playground', '/v1/graphql']
        
        for path in graphql_paths:
            try:
                url = f"{base_url}{path}"
                # Try POST with GraphQL introspection query
                introspection_query = {"query": "{ __schema { types { name } } }"}
                response = http_pool.post(url, json=introspection_query, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in str(data):
                            debug_print(f"    [GraphQL] Found at {path} (introspection enabled)")
                            return {
                                "endpoint": path,
                                "introspection_enabled": True,
                                "url": url
                            }
                    except:
                        pass
                
                # Try GET
                response = http_pool.get(url, timeout=5)
                if 'graphql' in response.text.lower() or 'graphiql' in response.text.lower():
                    debug_print(f"    [GraphQL] Found at {path}")
                    return {
                        "endpoint": path,
                        "introspection_enabled": False,
                        "url": url
                    }
            except:
                pass
        
        return None
    
    def _detect_websockets(self, base_url: str, http_pool) -> Optional[Dict[str, Any]]:
        """Detect WebSocket endpoints"""
        ws_url = base_url.replace('http://', 'ws://').replace('https://', 'wss://')
        ws_paths = ['/ws', '/websocket', '/socket.io', '/api/ws']
        
        for path in ws_paths:
            try:
                # Check for WebSocket upgrade headers
                url = f"{base_url}{path}"
                response = http_pool.get(url, timeout=5, headers={'Upgrade': 'websocket'})
                
                if response.status_code == 101 or 'websocket' in response.headers.get('Upgrade', '').lower():
                    debug_print(f"    [WebSocket] Found at {path}")
                    return {
                        "endpoint": path,
                        "url": f"{ws_url}{path}"
                    }
            except:
                pass
        
        return None
    
    def _test_api_vulnerabilities(self, base_url: str, endpoints: List[str], http_pool) -> List[Dict[str, Any]]:
        """Test common API vulnerabilities"""
        findings = []
        
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            
            # Test 1: Missing authentication
            try:
                response = http_pool.get(url, timeout=5)
                if response.status_code == 200 and 'api' in endpoint.lower():
                    findings.append({
                        "issue": f"API Endpoint Exposed: {endpoint}",
                        "severity": Severity.MEDIUM,
                        "description": f"API endpoint {endpoint} is accessible without authentication. May expose sensitive data or functionality.",
                        "recommendation": "Implement authentication and authorization for all API endpoints.",
                        "evidence": f"Status: {response.status_code}, URL: {url}"
                    })
            except:
                pass
            
            # Test 2: Information disclosure in error messages
            try:
                # Try to trigger error
                response = http_pool.get(f"{url}/invalid_endpoint_12345", timeout=5)
                if response.status_code >= 400:
                    error_text = response.text.lower()
                    if any(keyword in error_text for keyword in ['stack trace', 'exception', 'error at', 'file:', 'line:']):
                        findings.append({
                            "issue": f"Information Disclosure in API Errors: {endpoint}",
                            "severity": Severity.MEDIUM,
                            "description": f"API endpoint {endpoint} returns detailed error messages that may reveal internal structure.",
                            "recommendation": "Configure error handling to return generic error messages in production.",
                            "evidence": f"Error response contains stack trace or file paths"
                        })
            except:
                pass
            
            # Test 3: CORS misconfiguration
            try:
                response = http_pool.options(url, timeout=5, headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET'
                })
                cors_headers = {
                    k.lower(): v for k, v in response.headers.items()
                    if k.lower().startswith('access-control')
                }
                
                if cors_headers.get('access-control-allow-origin') == '*':
                    findings.append({
                        "issue": f"CORS Misconfiguration: {endpoint}",
                        "severity": Severity.HIGH,
                        "description": f"API endpoint {endpoint} allows requests from any origin (*). This enables CSRF attacks.",
                        "recommendation": "Restrict CORS to specific trusted origins only.",
                        "evidence": f"Access-Control-Allow-Origin: *"
                    })
            except:
                pass
        
        return findings
    
    def _test_graphql_vulnerabilities(self, base_url: str, graphql_info: Dict[str, Any], http_pool) -> List[Dict[str, Any]]:
        """Test GraphQL-specific vulnerabilities"""
        findings = []
        
        if graphql_info.get('introspection_enabled'):
            findings.append({
                "issue": "GraphQL Introspection Enabled",
                "severity": Severity.MEDIUM,
                "description": f"GraphQL endpoint at {graphql_info['endpoint']} has introspection enabled. Attackers can discover the entire schema.",
                "recommendation": "Disable GraphQL introspection in production environments.",
                "evidence": f"Introspection query successful at {graphql_info['url']}"
            })
        
        # Test for GraphQL query complexity/DoS
        try:
            # Try a deeply nested query
            complex_query = {"query": "{ " + "user { " * 100 + "id }" + " }" * 100}
            response = http_pool.post(graphql_info['url'], json=complex_query, timeout=10)
            
            if response.status_code == 200:
                findings.append({
                    "issue": "GraphQL Query Complexity Not Limited",
                    "severity": Severity.HIGH,
                    "description": f"GraphQL endpoint accepts complex nested queries without limits. This enables DoS attacks.",
                    "recommendation": "Implement query complexity limits and depth restrictions.",
                    "evidence": "Complex nested query accepted without rejection"
                })
        except:
            pass
        
        return findings



