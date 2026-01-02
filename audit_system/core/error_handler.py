"""
v17.6: Centralized Error Handling & Sanitization
Prevents errors from contaminating metrics and reports
"""
import traceback
from typing import Optional, Dict, Any
from enum import Enum
from ..core.debug import debug_print

class ErrorSeverity(str, Enum):
    """Error severity levels"""
    INTERNAL = "INTERNAL"  # Internal error, should not appear in reports
    WARNING = "WARNING"  # Warning that may affect results
    CRITICAL = "CRITICAL"  # Critical error that stops execution

class ErrorHandler:
    """Centralized error handling and sanitization"""
    
    _internal_errors: list = []  # Class-level list for internal errors
    _module_states: Dict[str, str] = {}  # Track module health
    
    @staticmethod
    def handle_error(error: Exception, context: str = "", 
                    severity: ErrorSeverity = ErrorSeverity.INTERNAL,
                    module: str = "") -> Optional[Dict[str, Any]]:
        """
        Handle errors gracefully.
        
        Returns:
            - None for INTERNAL errors (logged but not exposed)
            - Dict with error info for WARNING/CRITICAL (may be used in reports)
        """
        error_type = error.__class__.__name__
        error_msg = str(error)
        
        # Log internally
        ErrorHandler._internal_errors.append({
            'type': error_type,
            'message': error_msg,
            'context': context,
            'severity': severity.value,
            'module': module,
            'traceback': traceback.format_exc() if severity == ErrorSeverity.CRITICAL else None
        })
        
        # Update module state
        if module:
            if severity == ErrorSeverity.CRITICAL:
                ErrorHandler._module_states[module] = "FAILED"
            elif severity == ErrorSeverity.WARNING:
                ErrorHandler._module_states[module] = "DEGRADED"
            else:
                ErrorHandler._module_states[module] = "ERROR"
        
        # Log based on severity
        if severity == ErrorSeverity.INTERNAL:
            # Internal errors: log to debug only, never expose
            debug_print(f"  [INTERNAL ERROR] {module}: {error_type}: {error_msg} (context: {context})")
            return None  # Never expose internal errors
        
        elif severity == ErrorSeverity.WARNING:
            # Warnings: log and return sanitized info
            debug_print(f"  [⚠] {module}: {error_type}: {error_msg}")
            return {
                'type': 'warning',
                'module': module,
                'message': f"Warning in {module}: {error_type}",
                'sanitized': True
            }
        
        elif severity == ErrorSeverity.CRITICAL:
            # Critical: log with traceback
            debug_print(f"  [❌] {module}: CRITICAL ERROR: {error_type}: {error_msg}")
            debug_print(f"  [❌] Traceback: {traceback.format_exc()}")
            return {
                'type': 'critical',
                'module': module,
                'message': f"Critical error in {module}: {error_type}",
                'sanitized': True
            }
        
        return None
    
    @staticmethod
    def get_module_state(module: str) -> str:
        """Get current state of a module"""
        return ErrorHandler._module_states.get(module, "OK")
    
    @staticmethod
    def get_internal_errors() -> list:
        """Get list of internal errors (for debugging only)"""
        return ErrorHandler._internal_errors.copy()
    
    @staticmethod
    def clear_errors():
        """Clear error history"""
        ErrorHandler._internal_errors.clear()
        ErrorHandler._module_states.clear()
    
    @staticmethod
    def sanitize_finding(finding: Any) -> Optional[Any]:
        """
        Sanitize a finding to ensure it's valid.
        Returns None if finding is invalid.
        """
        try:
            # Check if finding has required attributes
            if not hasattr(finding, 'title') or not hasattr(finding, 'severity'):
                ErrorHandler.handle_error(
                    ValueError("Finding missing required attributes"),
                    context="sanitize_finding",
                    severity=ErrorSeverity.INTERNAL
                )
                return None
            
            # Check if severity is valid
            from ..core.models import Severity
            if not isinstance(finding.severity, Severity):
                ErrorHandler.handle_error(
                    ValueError(f"Invalid severity type: {type(finding.severity)}"),
                    context="sanitize_finding",
                    severity=ErrorSeverity.INTERNAL
                )
                return None
            
            return finding
            
        except Exception as e:
            ErrorHandler.handle_error(
                e,
                context="sanitize_finding",
                severity=ErrorSeverity.INTERNAL
            )
            return None


