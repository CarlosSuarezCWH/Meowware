"""
Intelligent Rate Limiting and Throttling
Adapts request rate based on server responses

Meowware v17.1 - Developed by Carlos Mancera
"""
import time
from typing import Optional

class IntelligentThrottler:
    """
    Intelligent throttling that adapts to server responses.
    Detects rate limiting (429, 503) and adjusts delay automatically.
    """
    
    def __init__(self, initial_delay: float = 1.0, min_delay: float = 0.5, max_delay: float = 10.0):
        self.current_delay = initial_delay
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.last_response_code: Optional[int] = None
        self.consecutive_429 = 0
        self.consecutive_200 = 0
    
    def adjust_delay(self, response_code: int):
        """
        Adjust delay based on response code.
        - 429 (Too Many Requests): Increase delay
        - 503 (Service Unavailable): Increase delay
        - 200 (OK): Decrease delay gradually
        """
        self.last_response_code = response_code
        
        if response_code == 429:
            # Too Many Requests - exponential backoff
            self.consecutive_429 += 1
            self.consecutive_200 = 0
            self.current_delay = min(self.current_delay * (1.5 ** self.consecutive_429), self.max_delay)
        elif response_code == 503:
            # Service Unavailable - increase delay
            self.consecutive_429 += 1
            self.consecutive_200 = 0
            self.current_delay = min(self.current_delay * 1.3, self.max_delay)
        elif response_code == 200:
            # Success - gradually decrease delay
            self.consecutive_200 += 1
            if self.consecutive_200 > 5:  # After 5 successful requests
                self.consecutive_429 = 0
                self.current_delay = max(self.current_delay * 0.95, self.min_delay)
        else:
            # Other codes - slight increase
            self.current_delay = min(self.current_delay * 1.1, self.max_delay)
    
    def get_delay(self) -> float:
        """Get current delay in seconds"""
        return self.current_delay
    
    def wait(self):
        """Wait for the current delay period"""
        time.sleep(self.current_delay)
    
    def reset(self):
        """Reset to initial delay"""
        self.current_delay = self.min_delay
        self.consecutive_429 = 0
        self.consecutive_200 = 0


