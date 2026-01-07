"""
Smart Cache System with TTL and Size Limits
v19.0 - Mejoras de caché con límites y persistencia

Meowware - Developed by Carlos Mancera
"""
import os
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path
from .config import get_config
from .logger import logger

config = get_config()
cache_config = config.cache


class SmartCache:
    """
    Intelligent caching system with different TTLs per data type:
    - WHOIS: 24 hours (rarely changes)
    - DNS: 1 hour (can change)
    - Tech stack: 6 hours (changes occasionally)
    - Vulnerabilities: 12 hours (updates periodically)
    - Infrastructure: 12 hours (relatively stable)
    
    v19.0: Added size limits and persistent storage option
    """
    
    CACHE_TTLS = {
        "whois": timedelta(hours=24),
        "dns": timedelta(hours=1),
        "tech_stack": timedelta(hours=6),
        "vulnerabilities": timedelta(hours=12),
        "infrastructure": timedelta(hours=12),
        "subdomain": timedelta(hours=6),
        "nmap": timedelta(hours=12),
        "default": timedelta(hours=1)
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or cache_config.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = cache_config.enabled
        self.max_size_mb = cache_config.max_size_mb
        self.persistent = cache_config.persistent
        
        # Inicializar caché persistente si está habilitado
        if self.persistent:
            self._init_persistent_cache()
        
        # Estadísticas
        self.hits = 0
        self.misses = 0
    
    def _init_persistent_cache(self):
        """Inicializar base de datos SQLite para caché persistente"""
        db_path = self.cache_dir / 'cache.db'
        self.db_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db_conn.row_factory = sqlite3.Row
        
        # Crear tabla si no existe
        self.db_conn.execute("""
            CREATE TABLE IF NOT EXISTS cache_entries (
                key TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                params TEXT,
                result TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                size_bytes INTEGER DEFAULT 0
            )
        """)
        
        # Índices para mejor rendimiento
        self.db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tool_target 
            ON cache_entries(tool, target)
        """)
        self.db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON cache_entries(timestamp)
        """)
        self.db_conn.commit()
        logger.debug(f"Caché persistente inicializado en {db_path}")
    
    def get_cache_key(self, tool: str, target: str, params: Dict = None) -> str:
        """Generate unique cache key"""
        key_string = f"{tool}:{target}"
        if params:
            key_string += f":{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, tool: str, target: str, params: Dict = None) -> Optional[Dict]:
        """Get cached result if valid"""
        if not self.enabled:
            return None
        
        key = self.get_cache_key(tool, target, params)
        
        # Intentar desde caché persistente primero
        if self.persistent:
            try:
                cursor = self.db_conn.execute(
                    "SELECT result, timestamp FROM cache_entries WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                
                if row:
                    cached_time = datetime.fromisoformat(row['timestamp'])
                    ttl = self.CACHE_TTLS.get(tool, self.CACHE_TTLS['default'])
                    
                    if datetime.now() - cached_time < ttl:
                        self.hits += 1
                        return json.loads(row['result'])
                    else:
                        # Expiró, eliminar
                        self.db_conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                        self.db_conn.commit()
                        self.misses += 1
                        return None
            except Exception as e:
                logger.warning(f"Error leyendo caché persistente: {e}")
        
        # Fallback a archivos JSON
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            self.misses += 1
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            cached_time = datetime.fromisoformat(data['timestamp'])
            ttl = self.CACHE_TTLS.get(tool, self.CACHE_TTLS['default'])
            
            if datetime.now() - cached_time < ttl:
                self.hits += 1
                return data['result']
            else:
                # Cache expired, delete file
                cache_file.unlink()
                self.misses += 1
                return None
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Corrupted cache file, delete it
            logger.warning(f"Caché corrupto eliminado: {cache_file} - {e}")
            cache_file.unlink()
            self.misses += 1
            return None
    
    def set(self, tool: str, target: str, result: Dict, params: Dict = None):
        """Store result in cache"""
        if not self.enabled:
            return
        
        # Verificar límite de tamaño antes de guardar
        if not self._check_size_limit():
            logger.warning("Límite de caché alcanzado, limpiando entradas antiguas")
            self._cleanup_old_entries()
        
        key = self.get_cache_key(tool, target, params)
        result_json = json.dumps(result)
        size_bytes = len(result_json.encode('utf-8'))
        timestamp = datetime.now().isoformat()
        
        # Guardar en caché persistente si está habilitado
        if self.persistent:
            try:
                self.db_conn.execute("""
                    INSERT OR REPLACE INTO cache_entries 
                    (key, tool, target, params, result, timestamp, size_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    key, tool, target,
                    json.dumps(params or {}),
                    result_json,
                    timestamp,
                    size_bytes
                ))
                self.db_conn.commit()
                return
            except Exception as e:
                logger.warning(f"Error guardando en caché persistente: {e}")
        
        # Fallback a archivos JSON
        cache_file = self.cache_dir / f"{key}.json"
        
        data = {
            "timestamp": timestamp,
            "tool": tool,
            "target": target,
            "params": params or {},
            "result": result
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Error guardando caché: {e}")
    
    def _check_size_limit(self) -> bool:
        """Verificar si el caché está dentro del límite de tamaño"""
        current_size_mb = self._get_current_size_mb()
        return current_size_mb < self.max_size_mb
    
    def _get_current_size_mb(self) -> float:
        """Obtener tamaño actual del caché en MB"""
        if self.persistent:
            try:
                cursor = self.db_conn.execute("SELECT SUM(size_bytes) as total FROM cache_entries")
                row = cursor.fetchone()
                total_bytes = row['total'] or 0
                return total_bytes / (1024 * 1024)
            except Exception:
                return 0.0
        
        # Calcular desde archivos
        total_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))
        return total_size / (1024 * 1024)
    
    def _cleanup_old_entries(self, target_mb: Optional[float] = None):
        """Limpiar entradas antiguas hasta alcanzar tamaño objetivo"""
        target_mb = target_mb or (self.max_size_mb * 0.8)  # Limpiar hasta 80% del límite
        
        if self.persistent:
            try:
                # Eliminar entradas más antiguas primero
                while self._get_current_size_mb() > target_mb:
                    cursor = self.db_conn.execute(
                        "SELECT key FROM cache_entries ORDER BY timestamp ASC LIMIT 10"
                    )
                    keys_to_delete = [row['key'] for row in cursor.fetchall()]
                    if not keys_to_delete:
                        break
                    
                    placeholders = ','.join('?' * len(keys_to_delete))
                    self.db_conn.execute(
                        f"DELETE FROM cache_entries WHERE key IN ({placeholders})",
                        keys_to_delete
                    )
                    self.db_conn.commit()
                    logger.debug(f"Eliminadas {len(keys_to_delete)} entradas de caché")
            except Exception as e:
                logger.warning(f"Error limpiando caché persistente: {e}")
        else:
            # Limpiar archivos JSON más antiguos
            files = sorted(
                self.cache_dir.glob("*.json"),
                key=lambda f: f.stat().st_mtime
            )
            
            while self._get_current_size_mb() > target_mb and files:
                try:
                    files[0].unlink()
                    files.pop(0)
                except Exception:
                    break
    
    def clear(self, tool: str = None):
        """Clear cache for specific tool or all cache"""
        if tool:
            # Clear only specific tool
            pattern = f"*_{tool}_*.json" if tool else "*.json"
            for cache_file in self.cache_dir.glob(pattern):
                cache_file.unlink()
        else:
            # Clear all
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            "enabled": self.enabled,
            "persistent": self.persistent,
            "total_size_mb": round(self._get_current_size_mb(), 2),
            "max_size_mb": self.max_size_mb,
            "cache_dir": str(self.cache_dir),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / (self.hits + self.misses) * 100, 2) if (self.hits + self.misses) > 0 else 0.0
        }
        
        if self.persistent:
            try:
                cursor = self.db_conn.execute("SELECT COUNT(*) as count FROM cache_entries")
                stats["total_entries"] = cursor.fetchone()['count']
            except Exception:
                stats["total_entries"] = 0
        else:
            cache_files = list(self.cache_dir.glob("*.json"))
            stats["total_entries"] = len(cache_files)
        
        return stats
    
    def close(self):
        """Cerrar conexiones de caché persistente"""
        if self.persistent and hasattr(self, 'db_conn'):
            self.db_conn.close()

