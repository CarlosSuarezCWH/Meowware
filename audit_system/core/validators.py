"""
Validación y Sanitización de Inputs
v19.0 - Seguridad y robustez

Meowware - Developed by Carlos Mancera
"""
import re
import ipaddress
from typing import Optional, List, Tuple
from urllib.parse import urlparse
from .config import get_config
from .logger import logger

config = get_config()


class ValidationError(Exception):
    """Excepción para errores de validación"""
    pass


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Valida que el target sea un dominio o IP válido.
    
    Args:
        target: String a validar
        
    Returns:
        Tuple (es_válido, tipo) donde tipo es 'domain', 'ip', o 'invalid'
    """
    if not target or not isinstance(target, str):
        return False, 'invalid'
    
    target = target.strip()
    
    # Validar IP
    try:
        ipaddress.ip_address(target)
        return True, 'ip'
    except ValueError:
        pass
    
    # Validar dominio
    # Regex básico para dominios (mejorable)
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        # Validaciones adicionales
        if len(target) > 253:  # Límite DNS
            return False, 'invalid'
        if target.count('.') > 127:  # Límite razonable
            return False, 'invalid'
        return True, 'domain'
    
    return False, 'invalid'


def validate_url(url: str) -> bool:
    """
    Valida que la URL sea válida.
    
    Args:
        url: URL a validar
        
    Returns:
        True si es válida
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_command_args(args: List[str]) -> List[str]:
    """
    Sanitiza argumentos de comandos para prevenir inyección.
    
    Args:
        args: Lista de argumentos
        
    Returns:
        Lista sanitizada
    """
    if not config.security.sanitize_commands:
        return args
    
    sanitized = []
    dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '\n', '\r']
    
    for arg in args:
        if not isinstance(arg, str):
            arg = str(arg)
        
        # Remover caracteres peligrosos
        for char in dangerous_chars:
            arg = arg.replace(char, '')
        
        # Limitar longitud
        if len(arg) > 1000:
            logger.warning(f"Argumento truncado por longitud: {arg[:50]}...")
            arg = arg[:1000]
        
        sanitized.append(arg)
    
    return sanitized


def validate_tool_name(tool: str) -> bool:
    """
    Valida que el nombre de herramienta esté permitido.
    
    Args:
        tool: Nombre de herramienta
        
    Returns:
        True si está permitida
    """
    if not config.security.validate_inputs:
        return True
    
    allowed = config.security.allowed_tools
    return tool.lower() in [t.lower() for t in allowed]


def validate_port(port: int) -> bool:
    """
    Valida que el puerto esté en rango válido.
    
    Args:
        port: Número de puerto
        
    Returns:
        True si es válido
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_hostname(hostname: str) -> bool:
    """
    Valida formato de hostname.
    
    Args:
        hostname: Hostname a validar
        
    Returns:
        True si es válido
    """
    if not hostname or len(hostname) > 253:
        return False
    
    # RFC 1123: hostname puede contener letras, números, guiones y puntos
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, hostname))


def sanitize_filename(filename: str) -> str:
    """
    Sanitiza nombre de archivo para prevenir path traversal.
    
    Args:
        filename: Nombre de archivo
        
    Returns:
        Nombre sanitizado
    """
    # Remover path separators
    filename = filename.replace('/', '').replace('\\', '')
    # Remover caracteres peligrosos
    filename = re.sub(r'[<>:"|?*]', '', filename)
    # Limitar longitud
    if len(filename) > 255:
        filename = filename[:255]
    return filename


def validate_and_sanitize_target(target: str) -> str:
    """
    Valida y sanitiza un target. Lanza excepción si es inválido.
    
    Args:
        target: Target a validar
        
    Returns:
        Target sanitizado
        
    Raises:
        ValidationError: Si el target es inválido
    """
    target = target.strip()
    
    is_valid, target_type = validate_target(target)
    if not is_valid:
        raise ValidationError(
            f"Target inválido: '{target}'. Debe ser una IP o dominio válido."
        )
    
    logger.debug(f"Target validado: {target} (tipo: {target_type})")
    return target


__all__ = [
    'ValidationError',
    'validate_target',
    'validate_url',
    'sanitize_command_args',
    'validate_tool_name',
    'validate_port',
    'validate_hostname',
    'sanitize_filename',
    'validate_and_sanitize_target'
]


