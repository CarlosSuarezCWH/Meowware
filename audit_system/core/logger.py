"""
Sistema de Logging Estándar
v19.0 - Reemplazo de debug.py con logging estándar

Meowware - Developed by Carlos Mancera
"""
import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from .config import get_config

# Configuración
config = get_config()
log_config = config.logging

# Crear logger principal
logger = logging.getLogger('meowware')
logger.setLevel(getattr(logging, log_config.level))

# Evitar duplicación de handlers
if not logger.handlers:
    # Handler para consola (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if log_config.debug_mode else logging.INFO)
    
    # Formato para consola (con colores si es posible)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # Handler para archivo (con rotación)
    if log_config.log_dir:
        log_file = Path(log_config.log_dir) / log_config.log_file
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=log_config.max_bytes,
            backupCount=log_config.backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, log_config.level))
        
        # Formato para archivo (más detallado)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)


# Funciones de compatibilidad con debug.py (para migración gradual)
def debug_print(message: str, prefix: str = "DEBUG"):
    """Compatibilidad con debug_print anterior"""
    if log_config.debug_mode:
        logger.debug(f"{prefix}: {message}")
    else:
        logger.info(message)


def debug_section(title: str):
    """Compatibilidad con debug_section anterior"""
    logger.info(f"{'='*60}")
    logger.info(f"[MEOWWARE SECTION] {title}")
    logger.info(f"{'='*60}")


def debug_tool(tool_name: str, command: str):
    """Compatibilidad con debug_tool anterior"""
    if log_config.debug_mode:
        cmd_str = ' '.join(command) if isinstance(command, list) else command
        logger.debug(f"[TOOL] Executing: {tool_name}")
        logger.debug(f"[TOOL] Command: {cmd_str}")


def debug_ai_prompt(prompt: str):
    """Compatibilidad con debug_ai_prompt anterior"""
    if log_config.debug_mode:
        logger.debug("[AI] >>> PROMPT TO LLM >>>")
        logger.debug(prompt)
        logger.debug("[AI] <<< END PROMPT <<<")


def debug_ai_response(response: str):
    """Compatibilidad con debug_ai_response anterior"""
    if log_config.debug_mode:
        logger.debug("[AI] >>> LLM RESPONSE >>>")
        logger.debug(response)
        logger.debug("[AI] <<< END RESPONSE <<<")


def is_debug() -> bool:
    """Compatibilidad con is_debug anterior"""
    return log_config.debug_mode


# Funciones mejoradas para logging estructurado
def log_tool_execution(tool: str, target: str, duration: float, success: bool = True):
    """Log estructurado de ejecución de herramienta"""
    status = "SUCCESS" if success else "FAILED"
    logger.info(
        f"Tool execution: tool={tool}, target={target}, duration={duration:.2f}s, status={status}",
        extra={
            'tool': tool,
            'target': target,
            'duration': duration,
            'success': success
        }
    )


def log_ai_call(model: str, duration: float, tokens: Optional[int] = None, cache_hit: bool = False):
    """Log estructurado de llamada a IA"""
    logger.info(
        f"AI call: model={model}, duration={duration:.2f}s, cache_hit={cache_hit}",
        extra={
            'model': model,
            'duration': duration,
            'tokens': tokens,
            'cache_hit': cache_hit
        }
    )


def log_finding(severity: str, title: str, host: Optional[str] = None):
    """Log estructurado de hallazgo"""
    logger.warning(
        f"Finding: severity={severity}, title={title}, host={host or 'N/A'}",
        extra={
            'severity': severity,
            'title': title,
            'host': host
        }
    )


# Exportar logger principal
__all__ = [
    'logger',
    'debug_print',
    'debug_section',
    'debug_tool',
    'debug_ai_prompt',
    'debug_ai_response',
    'is_debug',
    'log_tool_execution',
    'log_ai_call',
    'log_finding'
]


