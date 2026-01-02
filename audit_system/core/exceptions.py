class AuditError(Exception):
    """Base exception for the audit system."""
    pass

class TargetError(AuditError):
    """Raised when target validation or resolution fails."""
    pass

class ToolError(AuditError):
    """Raised when an external tool execution fails."""
    pass
