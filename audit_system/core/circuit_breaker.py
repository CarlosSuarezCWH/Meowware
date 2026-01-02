"""
Sistema de Circuit Breaker para Reintentos Inteligentes
Evita cascadas de fallos y mejora resiliencia
"""

import time
from typing import Callable, Any, Optional
from enum import Enum
from ..core.debug import debug_print


class CircuitState(Enum):
    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"  # Failing, reject requests
    HALF_OPEN = "HALF_OPEN"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit Breaker pattern para herramientas que fallan frecuentemente.
    Evita cascadas de fallos.
    """
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60, name: str = "default"):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.name = name
        self.failures = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        self.success_count = 0  # Para estado HALF_OPEN
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Ejecuta una función con protección de circuit breaker.
        """
        # Verificar estado del circuito
        if self.state == CircuitState.OPEN:
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
                # Intentar recuperación
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                debug_print(f"    [Circuit Breaker {self.name}] Attempting recovery (HALF_OPEN)")
            else:
                raise CircuitBreakerOpen(f"Circuit breaker {self.name} is OPEN. Service unavailable.")
        
        # Ejecutar función
        try:
            result = func(*args, **kwargs)
            
            # Éxito: resetear contador de fallos
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= 2:  # Necesita 2 éxitos consecutivos
                    self.state = CircuitState.CLOSED
                    self.failures = 0
                    debug_print(f"    [Circuit Breaker {self.name}] Service recovered (CLOSED)")
            elif self.state == CircuitState.CLOSED:
                self.failures = 0  # Reset en estado normal
            
            return result
            
        except Exception as e:
            # Falla: incrementar contador
            self.failures += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                # Falla en HALF_OPEN: volver a OPEN
                self.state = CircuitState.OPEN
                debug_print(f"    [Circuit Breaker {self.name}] Recovery failed, back to OPEN")
            elif self.failures >= self.failure_threshold:
                # Demasiados fallos: abrir circuito
                self.state = CircuitState.OPEN
                debug_print(f"    [Circuit Breaker {self.name}] Circuit OPEN after {self.failures} failures")
            
            raise


class CircuitBreakerOpen(Exception):
    """Excepción lanzada cuando el circuit breaker está abierto"""
    pass


def with_retry(max_attempts: int = 3, backoff_base: float = 2.0, 
               circuit_breaker: Optional[CircuitBreaker] = None):
    """
    Decorador para reintentos con backoff exponencial.
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    if circuit_breaker:
                        return circuit_breaker.call(func, *args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        delay = backoff_base ** attempt
                        debug_print(f"    [Retry] Attempt {attempt + 1}/{max_attempts} failed: {e}. Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                    else:
                        debug_print(f"    [Retry] All {max_attempts} attempts failed")
            
            raise last_exception
        return wrapper
    return decorator



