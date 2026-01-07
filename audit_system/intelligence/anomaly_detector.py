"""
Sistema de Detección de Anomalías y Razonamiento Analítico
Actúa como un analista de seguridad que detecta "algo huele mal"
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from ..core.models import Host, Service, Finding, Severity
from ..core.debug import debug_print


class AnomalyType(Enum):
    """Tipos de anomalías que pueden indicar problemas de seguridad"""
    UNUSUAL_PORT_COMBINATION = "unusual_port_combination"
    VERSION_MISMATCH = "version_mismatch"
    EXPOSED_SENSITIVE_SERVICE = "exposed_sensitive_service"
    SUSPICIOUS_HEADER = "suspicious_header"
    UNUSUAL_RESPONSE_PATTERN = "unusual_response_pattern"
    CONFIGURATION_ANOMALY = "configuration_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    CONTENT_ANOMALY = "content_anomaly"
    NETWORK_ANOMALY = "network_anomaly"


@dataclass
class Anomaly:
    """Representa una anomalía detectada"""
    type: AnomalyType
    severity: Severity
    description: str
    evidence: Dict[str, Any]
    confidence: float  # 0.0 a 1.0
    hypothesis: str  # Qué podría significar esta anomalía
    recommended_actions: List[str]  # Qué herramientas usar para investigar
    related_findings: List[str] = None  # IDs de findings relacionados


@dataclass
class Hypothesis:
    """Hipótesis sobre una posible vulnerabilidad o problema"""
    id: str
    title: str
    description: str
    confidence: float
    evidence: List[Dict[str, Any]]
    anomalies: List[Anomaly]
    status: str  # "active", "confirmed", "rejected", "investigating"
    recommended_tools: List[str]
    created_iter: int
    last_evidence_iter: int


class AnomalyDetector:
    """
    Detecta anomalías que podrían indicar problemas de seguridad.
    Actúa como un analista que dice "algo huele mal aquí"
    """
    
    def __init__(self):
        # Patrones conocidos de configuraciones sospechosas
        self.suspicious_patterns = {
            'exposed_admin': ['/admin', '/wp-admin', '/administrator', '/cpanel'],
            'debug_enabled': ['debug=true', 'debug=1', 'WP_DEBUG', 'display_errors'],
            'default_credentials': ['admin:admin', 'root:root', 'test:test'],
            'information_disclosure': ['server:', 'x-powered-by:', 'x-aspnet-version:'],
        }
        
        # Combinaciones de puertos sospechosas
        self.suspicious_port_combinations = [
            {3306, 80, 443},  # MySQL + Web = posible SQLi
            {5432, 80, 443},  # PostgreSQL + Web
            {27017, 80, 443},  # MongoDB + Web
            {5984, 80, 443},  # CouchDB + Web
            {6379, 80, 443},  # Redis + Web
            {9200, 80, 443},  # Elasticsearch + Web
        ]
    
    def detect_anomalies(self, host: Host, services: List[Service], 
                        web_context: Optional[Any] = None) -> List[Anomaly]:
        """
        Detecta anomalías en un host que podrían indicar problemas de seguridad.
        Razonamiento: "¿Hay algo que no debería estar aquí?"
        """
        anomalies = []
        
        # 1. Anomalía: Combinación sospechosa de puertos
        # v19.0: Reduced severity - DB+Web on same host is common in control panels (cPanel, Plesk, etc.)
        open_ports = {s.port for s in services if s.state == 'open'}
        
        # Check if this looks like a control panel (common ports for cPanel, Plesk, etc.)
        control_panel_ports = {2082, 2083, 2086, 2087, 2095, 2096, 8443, 8444}  # cPanel/Plesk ports
        is_likely_control_panel = bool(control_panel_ports.intersection(open_ports))
        
        # Also check hostname for control panel indicators
        hostname_lower = (host.hostname or "").lower() if hasattr(host, 'hostname') else ""
        is_control_panel_hostname = any(indicator in hostname_lower for indicator in ['panel', 'cpanel', 'plesk', 'admin', 'control'])
        
        for suspicious_combo in self.suspicious_port_combinations:
            if suspicious_combo.issubset(open_ports):
                db_port = next((p for p in suspicious_combo if p in [3306, 5432, 27017, 6379]), None)
                web_ports = {p for p in suspicious_combo if p in [80, 443, 8080, 8443]}
                
                if db_port and web_ports:
                    # v19.0: Reduce severity if it's likely a control panel - this is normal
                    if is_likely_control_panel or is_control_panel_hostname:
                        severity = Severity.INFO
                        description = f"Database port {db_port} exposed alongside web services. This is common in control panels (cPanel, Plesk) or custom applications. Verify that database access is properly restricted."
                        confidence = 0.5
                    else:
                        # Still note it, but as MEDIUM instead of HIGH
                        severity = Severity.MEDIUM
                        description = f"Database port {db_port} exposed alongside web services. This suggests poor network segmentation. Verify that database access is properly restricted and not publicly accessible."
                        confidence = 0.7
                    
                    anomalies.append(Anomaly(
                        type=AnomalyType.UNUSUAL_PORT_COMBINATION,
                        severity=severity,
                        description=description,
                        evidence={
                            'database_port': db_port,
                            'web_ports': list(web_ports),
                            'all_ports': list(open_ports),
                            'likely_control_panel': is_likely_control_panel or is_control_panel_hostname
                        },
                        confidence=confidence,
                        hypothesis="Database and web services on same host. Verify proper access controls and network segmentation.",
                        recommended_actions=[
                            "mysql-client" if db_port == 3306 else "postgres-client",
                            "nuclei:tags=exposure"
                        ]
                    ))
        
        # 2. Anomalía: Versiones desactualizadas o inconsistentes
        if web_context and hasattr(web_context, 'tech_versions'):
            tech_versions = web_context.tech_versions
            if isinstance(tech_versions, dict):
                for tech, version in tech_versions.items():
                    if self._is_old_version(tech, version):
                        anomalies.append(Anomaly(
                            type=AnomalyType.VERSION_MISMATCH,
                            severity=Severity.MEDIUM,
                            description=f"{tech} version {version} appears to be outdated or has known vulnerabilities.",
                            evidence={'technology': tech, 'version': version},
                            confidence=0.75,
                            hypothesis=f"Outdated {tech} version may have unpatched vulnerabilities. Check CVE database for {tech} {version}.",
                            recommended_actions=[
                                "cve_lookup",
                                f"nuclei:tags={tech.lower()},cve",
                                "version_scan"
                            ]
                        ))
        
        # 3. Anomalía: Servicios sensibles expuestos públicamente
        sensitive_services = {
            22: "SSH",
            3389: "RDP",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB",
            5984: "CouchDB",
            6379: "Redis",
            9200: "Elasticsearch",
            5985: "WinRM",
            5986: "WinRM HTTPS"
        }
        
        for service in services:
            if service.state == 'open' and service.port in sensitive_services:
                service_name = sensitive_services[service.port]
                anomalies.append(Anomaly(
                    type=AnomalyType.EXPOSED_SENSITIVE_SERVICE,
                    severity=Severity.HIGH if service.port in [3306, 5432, 27017, 1433] else Severity.MEDIUM,
                    description=f"{service_name} service exposed on port {service.port}. This should typically not be publicly accessible.",
                    evidence={
                        'service': service_name,
                        'port': service.port,
                        'version': service.version if hasattr(service, 'version') else None
                    },
                    confidence=0.9,
                    hypothesis=f"Public exposure of {service_name} increases attack surface. Check for weak authentication, default credentials, or misconfiguration.",
                    recommended_actions=[
                        f"{service_name.lower()}-scanner",
                        "nuclei:tags=exposure",
                        "credential-checker" if service.port in [22, 3389] else "auth-test"
                    ]
                ))
        
        # 4. Anomalía: Headers sospechosos o información expuesta
        if web_context and hasattr(web_context, 'headers'):
            headers = web_context.headers
            if isinstance(headers, dict):
                info_disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']
                for header in info_disclosure_headers:
                    if header in headers:
                        anomalies.append(Anomaly(
                            type=AnomalyType.SUSPICIOUS_HEADER,
                            severity=Severity.LOW,
                            description=f"Information disclosure header '{header}' exposes technology stack: {headers[header]}",
                            evidence={'header': header, 'value': headers[header]},
                            confidence=0.8,
                            hypothesis="Exposed technology information can aid attackers in crafting targeted exploits.",
                            recommended_actions=[
                                "nuclei:tags=information-disclosure",
                                "header-analysis",
                                "version-scan"
                            ]
                        ))
        
        # 5. Anomalía: Muchos puertos abiertos (superficie de ataque grande)
        if len(open_ports) > 15:
            anomalies.append(Anomaly(
                type=AnomalyType.NETWORK_ANOMALY,
                severity=Severity.MEDIUM,
                description=f"Unusually large number of open ports ({len(open_ports)}). This indicates a large attack surface.",
                evidence={'port_count': len(open_ports), 'ports': list(open_ports)},
                confidence=0.7,
                hypothesis="Large number of exposed services increases likelihood of misconfiguration or vulnerable service. Requires comprehensive audit.",
                recommended_actions=[
                    "comprehensive-port-scan",
                    "service-enumeration",
                    "nuclei:tags=exposure,cve"
                ]
            ))
        
        # 6. Anomalía: Respuestas HTTP inconsistentes
        if web_context and hasattr(web_context, 'behavioral_fingerprint'):
            behavioral = web_context.behavioral_fingerprint
            if isinstance(behavioral, dict):
                # Detectar respuestas inconsistentes que podrían indicar WAF o proxy
                if behavioral.get('response_time_variance', 0) > 2.0:
                    anomalies.append(Anomaly(
                        type=AnomalyType.TIMING_ANOMALY,
                        severity=Severity.LOW,
                        description="High variance in response times detected. Could indicate WAF, rate limiting, or load balancing.",
                        evidence={'variance': behavioral.get('response_time_variance')},
                        confidence=0.6,
                        hypothesis="Inconsistent response times may indicate defensive measures or infrastructure complexity. Adjust scan strategy.",
                        recommended_actions=[
                            "waf-detection",
                            "rate-limit-test",
                            "passive-scan"
                        ]
                    ))
        
        return anomalies
    
    def _is_old_version(self, tech: str, version: str) -> bool:
        """Determina si una versión es sospechosamente antigua"""
        if not version:
            return False
        
        # Versiones conocidas como antiguas o vulnerables
        old_versions = {
            'Apache': ['2.2', '2.0'],
            'Nginx': ['1.10', '1.12'],
            'PHP': ['5.6', '7.0', '7.1'],
            'WordPress': ['4.', '5.0', '5.1'],
            'MySQL': ['5.5', '5.6', '5.7'],
        }
        
        tech_lower = tech.lower()
        for tech_key, old_vers in old_versions.items():
            if tech_key.lower() in tech_lower:
                return any(version.startswith(v) for v in old_vers)
        
        return False


class HypothesisEngine:
    """
    Motor de hipótesis: Genera y gestiona hipótesis sobre posibles vulnerabilidades.
    Actúa como un analista que dice "si X, entonces probablemente Y"
    """
    
    def __init__(self):
        self.active_hypotheses: Dict[str, Hypothesis] = {}
        self.confirmed_hypotheses: List[Hypothesis] = []
        self.rejected_hypotheses: List[Hypothesis] = []
    
    def generate_hypothesis_from_anomaly(self, anomaly: Anomaly, iteration: int) -> Optional[Hypothesis]:
        """
        Genera una hipótesis a partir de una anomalía detectada.
        Razonamiento: "Esta anomalía sugiere que..."
        """
        # v19.0: Stable ID (ignore iteration) to prevent duplicate hypotheses
        # Use anomaly type and a hash of description/evidence as stable ID
        import hashlib
        evidence_str = str(sorted(anomaly.evidence.items())) if anomaly.evidence else ""
        content_hash = hashlib.md5((anomaly.type.value + anomaly.description + evidence_str).encode()).hexdigest()[:8]
        hypothesis_id = f"hyp_{anomaly.type.value}_{content_hash}"
        
        # Check if already active or confirmed
        if hypothesis_id in self.active_hypotheses:
            # Just update last_seen but don't create new one
            self.active_hypotheses[hypothesis_id].last_evidence_iter = iteration
            return self.active_hypotheses[hypothesis_id]
        
        # Check if already rejected/confirmed (optional, but good practice)
        for h in self.confirmed_hypotheses + self.rejected_hypotheses:
            if h.id == hypothesis_id:
                return h
        
        hypothesis = Hypothesis(
            id=hypothesis_id,
            title=anomaly.hypothesis,
            description=f"Based on anomaly: {anomaly.description}",
            confidence=anomaly.confidence,
            evidence=[anomaly.evidence],
            anomalies=[anomaly],
            status="active",
            recommended_tools=anomaly.recommended_actions,
            created_iter=iteration,
            last_evidence_iter=iteration
        )
        
        self.active_hypotheses[hypothesis_id] = hypothesis
        return hypothesis
    
    def update_hypothesis_with_evidence(self, hypothesis_id: str, 
                                       new_evidence: Dict[str, Any],
                                       iteration: int) -> None:
        """Actualiza una hipótesis con nueva evidencia"""
        if hypothesis_id in self.active_hypotheses:
            hypothesis = self.active_hypotheses[hypothesis_id]
            hypothesis.evidence.append(new_evidence)
            hypothesis.last_evidence_iter = iteration
            
            # Aumentar confianza si la evidencia confirma la hipótesis
            if new_evidence.get('confirms', False):
                hypothesis.confidence = min(hypothesis.confidence + 0.1, 1.0)
            
            # Si confianza es muy alta, marcar como confirmada
            if hypothesis.confidence >= 0.9:
                hypothesis.status = "confirmed"
                self.confirmed_hypotheses.append(hypothesis)
                del self.active_hypotheses[hypothesis_id]
    
    def kill_stale_hypotheses(self, current_iter: int, max_stale: int = 1) -> List[str]:
        """
        Elimina hipótesis que no han recibido evidencia reciente.
        Fuerza convergencia: si una hipótesis no avanza, se descarta.
        """
        killed = []
        for hyp_id, hypothesis in list(self.active_hypotheses.items()):
            stale_iters = current_iter - hypothesis.last_evidence_iter
            if stale_iters > max_stale:
                hypothesis.status = "rejected"
                self.rejected_hypotheses.append(hypothesis)
                del self.active_hypotheses[hyp_id]
                killed.append(hyp_id)
                debug_print(f"    [Hypothesis] Killed stale hypothesis: {hypothesis.title} (no evidence for {stale_iters} iterations)")
        
        return killed
    
    def get_active_hypotheses(self) -> List[Hypothesis]:
        """Retorna hipótesis activas ordenadas por confianza"""
        return sorted(
            self.active_hypotheses.values(),
            key=lambda h: h.confidence,
            reverse=True
        )
    
    def get_recommended_tools_for_hypotheses(self) -> List[str]:
        """Retorna herramientas recomendadas basadas en hipótesis activas"""
        tools = set()
        for hypothesis in self.get_active_hypotheses():
            tools.update(hypothesis.recommended_tools)
        return list(tools)


class SecurityAnalyst:
    """
    Analista de Seguridad Principal
    Combina detección de anomalías con generación de hipótesis.
    Actúa como un analista humano que razona sobre posibles problemas.
    """
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.hypothesis_engine = HypothesisEngine()
    
    def analyze_host(self, host: Host, services: List[Service], 
                    web_context: Optional[Any] = None,
                    iteration: int = 1) -> Dict[str, Any]:
        """
        Analiza un host como un analista de seguridad.
        Detecta anomalías, genera hipótesis, y recomienda acciones.
        """
        # v1.0: Simplified output - only show summary
        if iteration == 1:
            debug_print(f"    [Analysis] Analyzing host {host.ip} for anomalies and suspicious patterns...")
        
        # 1. Detectar anomalías
        anomalies = self.anomaly_detector.detect_anomalies(host, services, web_context)
        
        if anomalies and iteration == 1:
            debug_print(f"    [Analysis] Detected {len(anomalies)} anomalies")
        
        # 2. Generar hipótesis a partir de anomalías
        hypotheses = []
        for anomaly in anomalies:
            if anomaly.confidence >= 0.6:  # Solo hipótesis con confianza razonable
                hypothesis = self.hypothesis_engine.generate_hypothesis_from_anomaly(anomaly, iteration)
                hypotheses.append(hypothesis)
        
        # 3. Eliminar hipótesis estancadas
        killed = self.hypothesis_engine.kill_stale_hypotheses(iteration)
        
        # 4. Obtener herramientas recomendadas
        recommended_tools = self.hypothesis_engine.get_recommended_tools_for_hypotheses()
        
        # 5. Generar razonamiento analítico
        reasoning = self._generate_analytical_reasoning(anomalies, hypotheses)
        
        return {
            'anomalies': anomalies,
            'hypotheses': hypotheses,
            'active_hypotheses': self.hypothesis_engine.get_active_hypotheses(),
            'recommended_tools': recommended_tools,
            'reasoning': reasoning,
            'killed_hypotheses': killed
        }
    
    def _generate_analytical_reasoning(self, anomalies: List[Anomaly], 
                                      hypotheses: List[Hypothesis]) -> str:
        """
        Genera razonamiento analítico en lenguaje natural.
        Como un analista que explica "algo huele mal porque..."
        """
        if not anomalies:
            return "No significant anomalies detected. Standard security posture."
        
        reasoning_parts = []
        
        # Agrupar anomalías por tipo
        high_severity = [a for a in anomalies if a.severity in [Severity.CRITICAL, Severity.HIGH]]
        if high_severity:
            reasoning_parts.append(f"🔴 HIGH PRIORITY: {len(high_severity)} high-severity anomalies detected:")
            for anomaly in high_severity[:3]:  # Top 3
                reasoning_parts.append(f"  - {anomaly.description[:100]}")
        
        # Mencionar hipótesis más confiables
        if hypotheses:
            top_hypothesis = max(hypotheses, key=lambda h: h.confidence)
            reasoning_parts.append(f"💡 PRIMARY HYPOTHESIS: {top_hypothesis.title}")
            reasoning_parts.append(f"   Confidence: {top_hypothesis.confidence:.0%}")
            reasoning_parts.append(f"   Recommended tools: {', '.join(top_hypothesis.recommended_tools[:3])}")
        
        # Patrones sospechosos
        suspicious_patterns = []
        for anomaly in anomalies:
            if anomaly.type == AnomalyType.UNUSUAL_PORT_COMBINATION:
                suspicious_patterns.append("Poor network segmentation detected")
            elif anomaly.type == AnomalyType.EXPOSED_SENSITIVE_SERVICE:
                suspicious_patterns.append("Sensitive services publicly exposed")
            elif anomaly.type == AnomalyType.VERSION_MISMATCH:
                suspicious_patterns.append("Outdated software versions detected")
        
        if suspicious_patterns:
            reasoning_parts.append(f"⚠️  SUSPICIOUS PATTERNS: {', '.join(set(suspicious_patterns))}")
        
        return "\n".join(reasoning_parts) if reasoning_parts else "Standard analysis completed."



