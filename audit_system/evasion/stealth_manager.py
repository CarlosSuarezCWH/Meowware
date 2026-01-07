"""
Stealth Manager Module
Handles evasion techniques, rate limiting, and request obfuscation.
Meowware v19.0 - Stealth & Evasion
"""
import time
import random
from enum import IntEnum
from typing import Dict, Any, Optional

class StealthLevel(IntEnum):
    NONE = 0
    LEVEL_1 = 1  # User-Agent Rotation
    LEVEL_2 = 2  # + Randomized Delays
    LEVEL_3 = 3  # + Fragmented Scanning (where applicable), highly passive

class StealthManager:
    """
    Manages stealth configurations and request behavior.
    """
    
    def __init__(self, level: StealthLevel = StealthLevel.LEVEL_1):
        self.level = level
        self.security_detected = False # WAF/IPS detected
        self.block_count = 0
        
        # Common User-Agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]

    def set_level(self, level: StealthLevel):
        self.level = level

    def report_block(self):
        """Call when a 403/429/WAF block is encountered."""
        self.block_count += 1
        self.security_detected = True
        
        # Auto-escalate stealth if getting blocked
        if self.block_count >= 2 and self.level < StealthLevel.LEVEL_2:
            self.set_level(StealthLevel.LEVEL_2)
        elif self.block_count >= 5 and self.level < StealthLevel.LEVEL_3:
            self.set_level(StealthLevel.LEVEL_3)

    def get_headers(self) -> Dict[str, str]:
        """Get headers appropriate for current stealth level."""
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        # Spoofing for simple IP based filters (rarely works but low cost)
        if self.level >= StealthLevel.LEVEL_1:
            fake_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            headers["X-Forwarded-For"] = fake_ip
            headers["X-Real-IP"] = fake_ip

        return headers

    def throttle(self):
        """Apply delay based on stealth level."""
        if self.level == StealthLevel.LEVEL_2:
            time.sleep(random.uniform(0.5, 2.0))
        elif self.level >= StealthLevel.LEVEL_3:
            time.sleep(random.uniform(2.0, 5.0))

    def should_continue(self) -> bool:
        """Check if we should abort due to excessive blocking."""
        return self.block_count < 20
