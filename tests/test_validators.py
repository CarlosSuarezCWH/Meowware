"""
Tests para validación de inputs
v19.0 - Tests de validadores
"""
import sys
import os
import pytest

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from audit_system.core.validators import (
    validate_target,
    validate_url,
    sanitize_command_args,
    validate_tool_name,
    validate_port,
    validate_and_sanitize_target,
    ValidationError
)


def test_validate_target_ip():
    """Test validación de IP"""
    is_valid, target_type = validate_target("192.168.1.1")
    assert is_valid is True
    assert target_type == "ip"


def test_validate_target_domain():
    """Test validación de dominio"""
    is_valid, target_type = validate_target("example.com")
    assert is_valid is True
    assert target_type == "domain"
    
    is_valid, target_type = validate_target("subdomain.example.com")
    assert is_valid is True
    assert target_type == "domain"


def test_validate_target_invalid():
    """Test validación de target inválido"""
    is_valid, target_type = validate_target("not a valid target")
    assert is_valid is False
    assert target_type == "invalid"
    
    is_valid, target_type = validate_target("")
    assert is_valid is False


def test_validate_url():
    """Test validación de URL"""
    assert validate_url("http://example.com") is True
    assert validate_url("https://example.com/path") is True
    assert validate_url("not a url") is False
    assert validate_url("ftp://example.com") is True


def test_sanitize_command_args():
    """Test sanitización de argumentos"""
    args = ["nmap", "-p", "80; rm -rf /"]
    sanitized = sanitize_command_args(args)
    assert ";" not in sanitized[2]
    assert "rm" not in sanitized[2]


def test_validate_tool_name():
    """Test validación de nombre de herramienta"""
    assert validate_tool_name("nmap") is True
    assert validate_tool_name("nuclei") is True
    assert validate_tool_name("malicious_tool") is False


def test_validate_port():
    """Test validación de puerto"""
    assert validate_port(80) is True
    assert validate_port(443) is True
    assert validate_port(65535) is True
    assert validate_port(0) is False
    assert validate_port(65536) is False
    assert validate_port(-1) is False


def test_validate_and_sanitize_target():
    """Test validación y sanitización completa"""
    target = validate_and_sanitize_target("example.com")
    assert target == "example.com"
    
    target = validate_and_sanitize_target("  192.168.1.1  ")
    assert target == "192.168.1.1"
    
    with pytest.raises(ValidationError):
        validate_and_sanitize_target("invalid target")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


