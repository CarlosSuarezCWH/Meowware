"""
Smart Cache System with TTL
Caches results based on data type with appropriate TTLs

Meowware v16.0 - Developed by Carlos Mancera
"""
import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

class SmartCache:
    """
    Intelligent caching system with different TTLs per data type:
    - WHOIS: 24 hours (rarely changes)
    - DNS: 1 hour (can change)
    - Tech stack: 6 hours (changes occasionally)
    - Vulnerabilities: 12 hours (updates periodically)
    - Infrastructure: 12 hours (relatively stable)
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
    
    def __init__(self, cache_dir: str = ".meowware_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_cache_key(self, tool: str, target: str, params: Dict = None) -> str:
        """Generate unique cache key"""
        key_string = f"{tool}:{target}"
        if params:
            key_string += f":{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, tool: str, target: str, params: Dict = None) -> Optional[Dict]:
        """Get cached result if valid"""
        key = self.get_cache_key(tool, target, params)
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            cached_time = datetime.fromisoformat(data['timestamp'])
            ttl = self.CACHE_TTLS.get(tool, self.CACHE_TTLS['default'])
            
            if datetime.now() - cached_time < ttl:
                return data['result']
            else:
                # Cache expired, delete file
                cache_file.unlink()
                return None
        except (json.JSONDecodeError, KeyError, ValueError):
            # Corrupted cache file, delete it
            cache_file.unlink()
            return None
    
    def set(self, tool: str, target: str, result: Dict, params: Dict = None):
        """Store result in cache"""
        key = self.get_cache_key(tool, target, params)
        cache_file = self.cache_dir / f"{key}.json"
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool,
            "target": target,
            "params": params or {},
            "result": result
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Fail silently if cache write fails
    
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
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        return {
            "total_entries": len(cache_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir)
        }

