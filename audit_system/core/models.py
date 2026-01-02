from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import datetime

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
class HostRole(str, Enum):
    WEB = "WEB"
    MAIL = "MAIL"
    DB = "DB"
    DNS = "DNS"
    MGMT = "MGMT"
    EDGE = "EDGE"
    ORIGIN = "ORIGIN"
    UNKNOWN = "UNKNOWN"

class EvidenceType(str, Enum):
    RECON = "RECON"
    VULNERABILITY = "VULNERABILITY"
    MISCONFIG = "MISCONFIG"
    HEURISTIC = "HEURISTIC"

class BaseModel:
    def to_dict(self):
        """Robust recursive serialization for v18.5"""
        import dataclasses
        from enum import Enum
        import datetime
        
        def _serialize(obj):
            if dataclasses.is_dataclass(obj):
                result = {}
                for field in dataclasses.fields(obj):
                    value = getattr(obj, field.name)
                    result[field.name] = _serialize(value)
                return result
            elif isinstance(obj, list):
                return [_serialize(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            elif isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return obj
            
        return _serialize(self)

@dataclass
class Service(BaseModel):
    port: int
    protocol: str
    state: str
    name: str = "unknown"
    version: str = ""
    product: str = ""
    banner: str = "" # New in v10.2

@dataclass
class Finding(BaseModel):
    title: str
    category: str  # Network, DNS, Config
    severity: Severity
    description: str
    recommendation: str
    raw_output: str = "" # Phase 8: Appendix Data
    confidence_score: float = 0.5 # Phase 6: Reliability weighting
    evidence_type: EvidenceType = EvidenceType.HEURISTIC # Phase 3: Classification

    def __post_init__(self):
        """v13.0: Ensure severity is always an Enum."""
        if isinstance(self.severity, str):
            try: self.severity = Severity[self.severity.upper()]
            except: self.severity = Severity.INFO

@dataclass
class ScanTarget(BaseModel):
    input: str
    type: str
    resolved_ips: List[str]

@dataclass
class WebContext(BaseModel):
    url: str
    tech_stack: List[str] = field(default_factory=list)
    tech_versions: Dict[str, str] = field(default_factory=dict)  # {"Apache": "2.4.49", "PHP": "7.4.3"}
    waf_detected: bool = False
    waf_name: str = ""
    waf_type: str = "PASSIVE" # ACTIVE/PASSIVE
    cms_detected: str = ""
    cms_version: str = ""  # CMS version if detected
    cms_confidence: float = 0.0 # v18.5: Detection confidence
    subdomains: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict) # New in v10.2
    behavioral_fingerprint: Dict[str, Any] = field(default_factory=dict) # New in v14.0

@dataclass
class DNSInfo(BaseModel):
    records: Dict[str, List[str]] = field(default_factory=dict)
    registrar: str = ""
    creation_date: str = ""

@dataclass
class GlobalInsight(BaseModel):
    investigation_id: str
    target_host: str
    correlation_key: str  # e.g., "WAF-to-Origin", "Shared-Tech"
    summary: str
    risk_impact: str

@dataclass
class AIReasoning(BaseModel):
    context: str
    host_class: str = "UNKNOWN"
    interpretation: str = "" # Chain-of-Thought summary
    infrastructure_insights: List[str] = field(default_factory=list) # Phase 6: Clones/WAF pivots
    analysis: Dict[str, Any] = field(default_factory=dict)
    hypotheses: List[str] = field(default_factory=list)  # Active suspicions
    verification_goals: List[str] = field(default_factory=list)  # What to confirm/deny
    tools_selected: List[str] = field(default_factory=list)
    tools_excluded: List[str] = field(default_factory=list)
    stop_decision: bool = False
    stop_reason: str = ""
    iteration: int = 1
    evidence_summary: str = ""
    confidence: float = 0.0  # 0.0 to 1.0 confidence in current interpretation

@dataclass
class Host(BaseModel):
    ip: str
    hostname: str = ""
    aliases: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    os_guess: str = ""
    web_context: Optional[WebContext] = None 
    ssl_info: Optional[Dict[str, Any]] = None
    fingerprint_hash: str = "" # Phase 6: Host Fingerprinting
    classification: HostRole = HostRole.UNKNOWN # Primary role
    role_weights: Dict[HostRole, float] = field(default_factory=dict) # Multi-role weights
    is_internal: bool = False # v13.0: Cluster internal vs external
    asn: str = "" # v14.0: Infrastructure mapping
    geo_location: str = "" # v14.0: Geolocation
    ttl_map: Dict[str, int] = field(default_factory=dict) # v14.0: TTL analysis
    is_proxy: bool = False # New in v14.1
    origin_ip: Optional[str] = None # New in v14.1

    @property
    def tech_stack(self) -> List[str]:
        """v18.5: Proxy property to safe-access tech_stack from web_context"""
        if self.web_context:
            return self.web_context.tech_stack
        return []

@dataclass
class ScanResult(BaseModel):
    id: str
    timestamp: str
    target: ScanTarget
    hosts: List[Host] = field(default_factory=list) 
    dns: Optional[DNSInfo] = None
    findings: List[Finding] = field(default_factory=list)
    ai_reasoning: List[AIReasoning] = field(default_factory=list)
    global_insights: List[GlobalInsight] = field(default_factory=list) # Cross-host brain
    failed_subdomains: List[str] = field(default_factory=list) # v13.0: Recon history
    infrastructure_map: Dict[str, Any] = field(default_factory=dict) # v14.0: ASN/Geo summary
