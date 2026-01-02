"""
v17.5: Centralized JSON Serializer
Handles serialization of all Meowware objects (Finding, Anomaly, Host, Service, etc.)
"""
import json
import dataclasses
from enum import Enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from ..core.models import Finding, Host, Service, Severity, EvidenceType

class MeowwareSerializer:
    """Centralized serializer for all Meowware objects"""
    
    @staticmethod
    def serialize(obj: Any) -> Any:
        """Recursively serialize any Meowware object to JSON-serializable format"""
        if obj is None:
            return None
        
        # Handle Finding objects
        if isinstance(obj, Finding):
            return {
                'title': obj.title,
                'category': obj.category,
                'severity': obj.severity.value if hasattr(obj.severity, 'value') else str(obj.severity),
                'description': obj.description,
                'recommendation': obj.recommendation,
                'raw_output': obj.raw_output,
                'confidence_score': obj.confidence_score,
                'evidence_type': obj.evidence_type.value if hasattr(obj.evidence_type, 'value') else str(obj.evidence_type)
            }
        
        # Handle Anomaly objects (if exists)
        if hasattr(obj, '__class__') and 'Anomaly' in str(obj.__class__):
            return {
                'type': getattr(obj, 'type', {}).value if hasattr(getattr(obj, 'type', None), 'value') else str(getattr(obj, 'type', '')),
                'description': getattr(obj, 'description', ''),
                'confidence': getattr(obj, 'confidence', 0.0),
                'severity': getattr(obj, 'severity', {}).value if hasattr(getattr(obj, 'severity', None), 'value') else str(getattr(obj, 'severity', ''))
            }
        
        # Handle dataclasses
        if dataclasses.is_dataclass(obj):
            result = {}
            for field in dataclasses.fields(obj):
                value = getattr(obj, field.name, None)
                result[field.name] = MeowwareSerializer.serialize(value)
            return result
        
        # Handle lists
        if isinstance(obj, list):
            return [MeowwareSerializer.serialize(item) for item in obj]
        
        # Handle dicts
        if isinstance(obj, dict):
            return {k: MeowwareSerializer.serialize(v) for k, v in obj.items()}
        
        # Handle Enums
        if isinstance(obj, Enum):
            return obj.value
        
        # Handle datetime
        if isinstance(obj, datetime):
            return obj.isoformat()
        
        # Handle primitives
        if isinstance(obj, (str, int, float, bool)):
            return obj
        
        # Fallback: convert to string
        return str(obj)
    
    @staticmethod
    def to_json(obj: Any, indent: int = 2) -> str:
        """Convert object to JSON string"""
        try:
            serialized = MeowwareSerializer.serialize(obj)
            return json.dumps(serialized, indent=indent, ensure_ascii=False)
        except Exception as e:
            # Ultimate fallback
            return json.dumps({"error": f"Serialization failed: {str(e)}", "object": str(obj)}, default=str)

