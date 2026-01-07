"""
Sistema de Configuración Centralizado
v19.0 - Mejoras de arquitectura

Meowware - Developed by Carlos Mancera
"""
import os
from typing import Optional, Literal
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Cargar .env si existe
load_dotenv()


@dataclass
class AIConfig:
    """Configuración de IA/LLM"""
    provider: Literal['deepseek', 'ollama'] = 'deepseek'
    deepseek_api_key: Optional[str] = None
    ollama_url: str = 'http://localhost:11434/api/generate'
    model: str = 'deepseek-chat'
    timeout: int = 120
    max_retries: int = 3
    temperature: float = 0.3
    max_tokens: int = 2000
    
    def __post_init__(self):
        """Validar configuración de IA"""
        if self.provider == 'deepseek':
            self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY', self.deepseek_api_key)
            if not self.deepseek_api_key:
                raise ValueError(
                    "DEEPSEEK_API_KEY requerida cuando LLM_PROVIDER=deepseek. "
                    "Configúrala en .env o como variable de entorno."
                )
        elif self.provider == 'ollama':
            self.ollama_url = os.getenv('LLM_URL', self.ollama_url)


@dataclass
class PerformanceConfig:
    """Configuración de rendimiento"""
    max_workers: int = 3
    request_timeout: int = 30
    rate_limit_per_minute: int = 60
    enable_async: bool = False  # Para futura implementación async
    
    def __post_init__(self):
        """Ajustar workers según CPU disponible"""
        cpu_count = os.cpu_count() or 4
        max_workers_env = os.getenv('MAX_WORKERS')
        if max_workers_env:
            self.max_workers = int(max_workers_env)
        else:
            # Usar CPU count pero limitar a 10 para no sobrecargar
            self.max_workers = min(cpu_count, 10)
        
        self.request_timeout = int(os.getenv('REQUEST_TIMEOUT', self.request_timeout))
        self.rate_limit_per_minute = int(os.getenv('RATE_LIMIT_PER_MINUTE', self.rate_limit_per_minute))


@dataclass
class CacheConfig:
    """Configuración de caché"""
    enabled: bool = True
    max_size_mb: int = 100
    ttl_seconds: int = 3600
    cache_dir: str = '.meowware_cache'
    persistent: bool = True  # Usar SQLite para persistencia
    
    def __post_init__(self):
        """Cargar configuración de caché"""
        cache_enabled = os.getenv('ENABLE_CACHE', '1')
        self.enabled = cache_enabled == '1' or cache_enabled.lower() == 'true'
        self.max_size_mb = int(os.getenv('CACHE_MAX_SIZE', self.max_size_mb))
        self.ttl_seconds = int(os.getenv('CACHE_TTL', self.ttl_seconds))
        self.cache_dir = os.getenv('CACHE_DIR', self.cache_dir)


@dataclass
class LoggingConfig:
    """Configuración de logging"""
    level: str = 'INFO'
    debug_mode: bool = False
    log_dir: str = './logs'
    log_file: str = 'meowware.log'
    max_bytes: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    structured: bool = False  # JSON logs
    
    def __post_init__(self):
        """Cargar configuración de logging"""
        debug_mode = os.getenv('DEBUG_MODE', '0')
        self.debug_mode = debug_mode == '1' or debug_mode.lower() == 'true'
        
        log_level = os.getenv('LOG_LEVEL', self.level).upper()
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level in valid_levels:
            self.level = log_level
        else:
            self.level = 'INFO'
        
        self.log_dir = os.getenv('LOG_DIR', self.log_dir)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)


@dataclass
class DatabaseConfig:
    """Configuración de base de datos"""
    db_path: str = '.meowware_db/scan_history.db'
    pool_size: int = 5
    timeout: int = 30
    
    def __post_init__(self):
        """Cargar configuración de BD"""
        self.db_path = os.getenv('DB_PATH', self.db_path)
        self.pool_size = int(os.getenv('DB_POOL_SIZE', self.pool_size))


@dataclass
class SecurityConfig:
    """Configuración de seguridad"""
    wpscan_api_token: Optional[str] = None
    validate_inputs: bool = True
    sanitize_commands: bool = True
    allowed_tools: set = field(default_factory=lambda: {
        'nmap', 'nuclei', 'wpscan', 'joomscan', 'droopescan',
        'nikto', 'testssl', 'sqlmap', 'dirsearch', 'feroxbuster',
        'amass', 'subfinder', 'whatweb', 'whois', 'dig'
    })
    
    def __post_init__(self):
        """Cargar tokens de seguridad"""
        self.wpscan_api_token = os.getenv('WPSCAN_API_TOKEN', self.wpscan_api_token)


@dataclass
class Config:
    """Configuración centralizada de Meowware"""
    ai: AIConfig = field(default_factory=AIConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    def __post_init__(self):
        """Validar toda la configuración"""
        self.validate()
    
    def validate(self) -> bool:
        """Validar que la configuración sea correcta"""
        errors = []
        
        # Validar AI config
        try:
            self.ai.__post_init__()
        except ValueError as e:
            errors.append(f"AI Config: {e}")
        
        # Validar otros configs
        self.performance.__post_init__()
        self.cache.__post_init__()
        self.logging.__post_init__()
        self.database.__post_init__()
        self.security.__post_init__()
        
        if errors:
            raise ValueError(f"Errores de configuración:\n" + "\n".join(f"  - {e}" for e in errors))
        
        return True
    
    @classmethod
    def load(cls) -> 'Config':
        """Cargar configuración desde entorno"""
        config = cls()
        config.validate()
        return config


# Singleton global
_config: Optional[Config] = None


def get_config() -> Config:
    """Obtener instancia singleton de configuración"""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def reload_config() -> Config:
    """Recargar configuración (útil para tests)"""
    global _config
    _config = Config.load()
    return _config


