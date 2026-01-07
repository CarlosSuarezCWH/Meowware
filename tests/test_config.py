"""
Tests para sistema de configuración
v19.0 - Tests de configuración centralizada
"""
import sys
import os
import pytest
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from audit_system.core.config import Config, AIConfig, PerformanceConfig, get_config, reload_config


def test_config_loading():
    """Test que la configuración se carga correctamente"""
    config = get_config()
    assert config is not None
    assert config.ai is not None
    assert config.performance is not None
    assert config.cache is not None
    assert config.logging is not None


def test_performance_config():
    """Test configuración de rendimiento"""
    perf = PerformanceConfig()
    assert perf.max_workers > 0
    assert perf.request_timeout > 0
    assert perf.rate_limit_per_minute > 0


def test_cache_config():
    """Test configuración de caché"""
    from audit_system.core.config import CacheConfig
    
    cache = CacheConfig()
    assert cache.max_size_mb > 0
    assert cache.ttl_seconds > 0
    assert isinstance(cache.enabled, bool)


def test_ai_config_validation():
    """Test validación de configuración de IA"""
    # Test con API key faltante (debería fallar si provider=deepseek)
    import os
    original_key = os.environ.get('DEEPSEEK_API_KEY')
    
    try:
        # Remover API key temporalmente
        if 'DEEPSEEK_API_KEY' in os.environ:
            del os.environ['DEEPSEEK_API_KEY']
        
        # Cambiar provider a ollama para que no falle
        os.environ['LLM_PROVIDER'] = 'ollama'
        reload_config()
        
        config = get_config()
        assert config.ai.provider == 'ollama'
        
    finally:
        # Restaurar
        if original_key:
            os.environ['DEEPSEEK_API_KEY'] = original_key
        os.environ['LLM_PROVIDER'] = 'deepseek'
        reload_config()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


