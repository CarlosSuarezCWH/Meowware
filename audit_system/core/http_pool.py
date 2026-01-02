"""
HTTP Connection Pool
Reusable HTTP connections with retry strategy and intelligent throttling

Meowware v17.1 - Developed by Carlos Mancera
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
import time
import urllib3
from .intelligent_throttler import IntelligentThrottler

# v17.1: Suprimir warnings de SSL no verificado para output más limpio
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPConnectionPool:
    """
    Reusable HTTP connection pool with automatic retry
    Reduces connection overhead and improves performance
    """
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 1.0,
                 pool_connections: int = 10, pool_maxsize: int = 20,
                 timeout: int = 30):
        self.session = requests.Session()
        self.timeout = timeout
        # v17.1: Intelligent throttling
        self.throttler = IntelligentThrottler()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
            raise_on_status=False
        )
        
        # Create adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        # Mount adapters for both HTTP and HTTPS
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with connection pooling and intelligent throttling"""
        kwargs.setdefault('timeout', self.timeout)
        # v17.1: Apply intelligent throttling
        self.throttler.wait()
        response = self.session.get(url, **kwargs)
        # Adjust throttling based on response
        self.throttler.adjust_delay(response.status_code)
        return response
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with connection pooling and intelligent throttling"""
        kwargs.setdefault('timeout', self.timeout)
        # v17.1: Apply intelligent throttling
        self.throttler.wait()
        response = self.session.post(url, **kwargs)
        # Adjust throttling based on response
        self.throttler.adjust_delay(response.status_code)
        return response
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HEAD request with connection pooling"""
        kwargs.setdefault('timeout', self.timeout)
        return self.session.head(url, **kwargs)
    
    def close(self):
        """Close all connections"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

# Global instance
_http_pool: Optional[HTTPConnectionPool] = None

def get_http_pool() -> HTTPConnectionPool:
    """Get or create global HTTP pool instance"""
    global _http_pool
    if _http_pool is None:
        _http_pool = HTTPConnectionPool()
    return _http_pool

