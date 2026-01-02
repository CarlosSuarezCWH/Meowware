import sys
import os
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from audit_system.core.models import Host, Service, Finding, Severity, EvidenceType, WebContext, ScanResult, ScanTarget

def test_serialization():
    print("Testing Meowware v18.5 Recursive Serialization...")
    
    # Create a complex nested structure
    service = Service(port=443, protocol="tcp", state="open", name="https", version="2.4.41", product="Apache")
    finding = Finding(
        title="Complex Finding",
        category="Web",
        severity=Severity.HIGH,
        description="A nested finding",
        recommendation="Fix it",
        confidence_score=0.85,
        evidence_type=EvidenceType.VULNERABILITY
    )
    
    web_ctx = WebContext(
        url="https://example.com",
        tech_stack=["Apache", "PHP"],
        tech_versions={"Apache": "2.4.41"},
        cms_detected="WordPress",
        cms_version="6.4"
    )
    
    host = Host(
        ip="1.2.3.4",
        hostname="example.com",
        services=[service],
        web_context=web_ctx
    )
    
    target = ScanTarget(input="example.com", type="domain", resolved_ips=["1.2.3.4"])
    
    result = ScanResult(
        id="test-scan-123",
        timestamp=datetime.now().isoformat(),
        target=target,
        hosts=[host],
        findings=[finding]
    )
    
    try:
        serialized = result.to_dict()
        print(" [✓] result.to_dict() executed successfully")
        
        # Verify JSON serializability
        json_output = json.dumps(serialized)
        print(" [✓] json.dumps() successful")
        
        # Check specific nested values
        assert serialized['hosts'][0]['web_context']['cms_detected'] == "WordPress"
        assert serialized['findings'][0]['severity'] == "HIGH" # Enum as value
        print(" [✓] Data integrity verified")
        
        print("\nTEST PASSED")
    except Exception as e:
        print(f"\n [✗] TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_serialization()
