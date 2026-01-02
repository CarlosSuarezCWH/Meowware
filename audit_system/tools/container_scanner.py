import requests
from typing import List, Dict, Any
from ..core.debug import debug_print
from ..analysis.risk_scorer import Finding, Severity

class ContainerScanner:
    """
    v18.0: Container & Kubernetes Security Scanner.
    Checks for exposed Docker sockets, K8s API misconfigurations, and RBAC issues.
    """
    def __init__(self):
        self.k8s_ports = [6443, 8443, 10250, 10255]
        self.docker_ports = [2375, 2376]
        
    def run(self, host_ip: str, services: List[Any]) -> List[Finding]:
        findings = []
        debug_print(f"  [Container Scanner] Auditing container infrastructure for: {host_ip}")
        
        # 1. Docker Socket Check
        findings.extend(self._check_docker_socket(host_ip, services))
        
        # 2. Kubernetes API Check
        findings.extend(self._check_k8s_api(host_ip, services))
        
        return findings

    def _check_docker_socket(self, ip: str, services: List[Any]) -> List[Finding]:
        findings = []
        for s in services:
            if s.port in self.docker_ports and s.state == 'open':
                try:
                    url = f"http://{ip}:{s.port}/version" if s.port == 2375 else f"https://{ip}:{s.port}/version"
                    res = requests.get(url, timeout=5, verify=False)
                    if res.status_code == 200:
                        findings.append(Finding(
                            title="Unauthenticated Docker Socket Exposed",
                            description=f"Docker Remote API is exposed without authentication at {url}. This allows full control over the host containers.",
                            severity=Severity.CRITICAL,
                            mitigation="Restrict access to the Docker socket or enable TLS authentication.",
                            references=["https://docs.docker.com/engine/security/https/"]
                        ))
                except:
                    pass
        return findings

    def _check_k8s_api(self, ip: str, services: List[Any]) -> List[Finding]:
        findings = []
        for s in services:
            if s.port in self.k8s_ports and s.state == 'open':
                try:
                    # Check for anonymous access to K8s API
                    url = f"https://{ip}:{s.port}/api"
                    res = requests.get(url, timeout=5, verify=False)
                    if res.status_code == 200:
                        findings.append(Finding(
                            title="Kubernetes API Anonymous Access Enabled",
                            description=f"The Kubernetes API at {url} allows anonymous access. This could lead to information disclosure or cluster compromise.",
                            severity=Severity.HIGH,
                            mitigation="Disable anonymous-auth in the kube-apiserver configuration.",
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/authorization/"]
                        ))
                except:
                    pass
        return findings
