
import unittest
from audit_system.core.models import Finding, Severity, EvidenceType, FindingStatus
from audit_system.core.serializer import MeowwareSerializer
from audit_system.core.finding_validator import FindingValidator
from audit_system.intelligence.anomaly_detector import AnomalyDetector, HypothesisEngine, Anomaly, AnomalyType

class TestV19Improvements(unittest.TestCase):
    def test_serialization(self):
        """Test that Finding with status is serialized correctly"""
        f = Finding(
            title="Test Finding",
            category="Test",
            severity=Severity.HIGH,
            description="Test description",
            recommendation="Fix it",
            status=FindingStatus.POTENTIAL
        )
        serialized = MeowwareSerializer.serialize(f)
        self.assertEqual(serialized['status'], "POTENTIAL")
        self.assertEqual(serialized['severity'], "HIGH")
    
    def test_critical_criteria_refinement(self):
        """Test that CRITICAL findings are downgraded without evidence"""
        # Case 1: CRITICAL without evidence -> Should be downgraded
        f = Finding(
            title="Critical SQL Injection",
            category="Injection",
            severity=Severity.CRITICAL,
            description="Potential SQL injection detected based on heuristics.",
            recommendation="Fix it",
            evidence_type=EvidenceType.HEURISTIC
            # No raw_output, no 'payload'/'confirmed' in description
        )
        
        validated = FindingValidator.validate_finding(f)
        
        # SQLi logic downgrades "Potential SQLi" to MEDIUM (line 66 in validator)
        # This is correct behavior for SQLi
        self.assertEqual(validated.severity, Severity.MEDIUM)
        self.assertEqual(validated.status, FindingStatus.POTENTIAL)

    def test_generic_critical_downgrade(self):
        """Test generic CRITICAL finding downgrade logic"""
        # Generic CRITICAL without evidence
        f = Finding(
            title="Generic Remote Code Execution",
            category="RCE", 
            severity=Severity.CRITICAL,
            description="Potential RCE detected via heuristic.",
            recommendation="Patch it",
            evidence_type=EvidenceType.HEURISTIC
        )
        
        # Should bypass SQLi logic and hit the generic Critical Guard
        validated = FindingValidator.validate_finding(f)
        
        # Generic guard downgrades to HIGH
        self.assertEqual(validated.severity, Severity.HIGH)
        # Status likely remains POTENTIAL/LIKELY depending on logic, or None (defaults to POTENTIAL in serialization)

        
        # Case 2: CRITICAL with strong evidence -> Should remain CRITICAL
        f2 = Finding(
            title="Confirmed SQL Injection",
            category="Injection",
            severity=Severity.CRITICAL,
            description="SQL Injection confirmed. Payload: ' OR 1=1--. Response: Database Error.",
            recommendation="Fix it",
            raw_output="Payload successful, database version leaked.",
            evidence_type=EvidenceType.VULNERABILITY
        )
        validated2 = FindingValidator.validate_finding(f2)
        self.assertEqual(validated2.severity, Severity.CRITICAL)
        self.assertEqual(validated2.status, FindingStatus.CONFIRMED)

    def test_hypothesis_deduplication(self):
        """Test that identical anomalies generate stable Hypothesis IDs"""
        engine = HypothesisEngine()
        anomaly = Anomaly(
            type=AnomalyType.UNUSUAL_PORT_COMBINATION,
            severity=Severity.MEDIUM,
            description="DB and Web on same host",
            evidence={'ports': [80, 3306]},
            confidence=0.7,
            hypothesis="Poor segmentation",
            recommended_actions=["audit"]
        )
        
        # Iteration 1
        h1 = engine.generate_hypothesis_from_anomaly(anomaly, iteration=1)
        id1 = h1.id
        
        # Iteration 2 (same anomaly)
        h2 = engine.generate_hypothesis_from_anomaly(anomaly, iteration=2)
        id2 = h2.id
        
        self.assertEqual(id1, id2)
        self.assertEqual(h1, h2) # Should be the exact same object reference if returned from active list

if __name__ == '__main__':
    unittest.main()
