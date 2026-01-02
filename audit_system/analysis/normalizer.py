import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from ..core.models import Service, DNSInfo

class Normalizer:
    @staticmethod
    def parse_nmap_xml(xml_content: str) -> List[Service]:
        """Parses Nmap XML to extract services."""
        services = []
        try:
            root = ET.fromstring(xml_content)
            # Find the host that is 'up' - simplistic approach for MVP
            for host in root.findall('host'):
                for port_element in host.findall('.//port'):
                    port_id = int(port_element.get('portid'))
                    protocol = port_element.get('protocol')
                    state_el = port_element.find('state')
                    service_el = port_element.find('service')
                    
                    state = state_el.get('state') if state_el is not None else 'unknown'
                    
                    service_name = 'unknown'
                    version = ''
                    product = ''
                    
                    if service_el is not None:
                        service_name = service_el.get('name', 'unknown')
                        version = service_el.get('version', '')
                        product = service_el.get('product', '')

                    services.append(Service(
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        name=service_name,
                        version=version,
                        product=product
                    ))
        except Exception:
            pass
        return services

    @staticmethod
    def parse_domain_info(whois_text: str, dig_results: Dict[str, str]) -> DNSInfo:
        """Combines Whois and Dig info into DNSInfo model."""
        # Whois Parsing
        registrar = ""
        creation = ""
        
        r_match = re.search(r'Registrar:\s*(.*)', whois_text, re.IGNORECASE)
        if r_match: registrar = r_match.group(1).strip()
        
        c_match = re.search(r'Creation Date:\s*(.*)', whois_text, re.IGNORECASE)
        if c_match: creation = c_match.group(1).strip()

        # Dig Parsing
        records = {}
        for rtype, output in dig_results.items():
            if "Error:" not in output:
                lines = [line.strip() for line in output.split('\n') if line.strip()]
                records[rtype] = lines
            else:
                records[rtype] = []
        
        return DNSInfo(
            records=records,
            registrar=registrar,
            creation_date=creation
        )
    @staticmethod
    def calculate_fingerprint(services: List[Service]) -> str:
        """v12.5: Generates a hash based on open ports and versions for host correlation."""
        import hashlib
        data = sorted([f"{s.port}:{s.product}:{s.version}" for s in services if s.state == 'open'])
        if not data: return ""
        return hashlib.md5(",".join(data).encode()).hexdigest()

    @staticmethod
    def classify_host(services: List[Service], web_context: Any = None) -> Any:
        """v18.5: Balanced Host Role Engine with CMS/WAF awareness."""
        from ..core.models import HostRole
        ports = [s.port for s in services if s.state == 'open']
        weights = {r: 0.0 for r in HostRole}
        
        # 1. Scoring logic - Base services
        if any(p in [25, 465, 587] for p in ports): weights[HostRole.MAIL] += 0.8  # Reduced from 0.9
        if any(p in [110, 143, 993, 995] for p in ports): weights[HostRole.MAIL] += 0.2
        
        if 53 in ports: weights[HostRole.DNS] += 0.9
        if any(p in [3306, 5432, 1433, 27017] for p in ports): weights[HostRole.DB] += 0.9
        
        # 2. Web & Edge Prioritization
        has_web = any(p in [80, 443, 8080, 8443] for p in ports)
        if has_web:
            weights[HostRole.WEB] += 0.8
            # Bonus if CMS is detected
            if web_context and getattr(web_context, 'cms_detected', ''):
                weights[HostRole.WEB] += 0.4  # Total 1.2, wins over MAIL
        
        if web_context and getattr(web_context, 'waf_detected', False):
            weights[HostRole.EDGE] += 1.5  # Strong recommendation for EDGE
            
        if 22 in ports: weights[HostRole.MGMT] += 0.2
        if len(ports) < 2 and 22 in ports: weights[HostRole.MGMT] += 0.6

        # 3. Determine dominant role
        primary = max(weights, key=weights.get)
        if weights[primary] == 0: primary = HostRole.UNKNOWN
        
        return primary, {r: round(v, 2) for r, v in weights.items() if v > 0}

    @staticmethod
    def get_cluster_id(host: Any) -> str:
        """v13.0: Generates an infrastructure cluster ID based on ASN, Banners, and Ports."""
        import hashlib
        # Simple clustering: combine fingerprint with a slice of IP (subnet) or ASN if available
        # Here we use fingerprint + sorted banners as a proxy for 'identical infrastructure'
        banners = sorted([s.banner for s in host.services if s.banner])
        key = f"{host.fingerprint_hash}:{','.join(banners)}"
        return hashlib.md5(key.encode()).hexdigest()
