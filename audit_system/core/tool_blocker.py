"""
v17.5: Tool Blocker with Penalty System
Prevents LLM from suggesting blocked tools repeatedly
"""
from typing import Dict, List, Set
from ..core.debug import debug_print

class ToolBlocker:
    """Manages tool blocking with penalty system"""
    
    def __init__(self):
        # Global blocked tools for this session
        self.session_blocked: Dict[str, Set[str]] = {}  # {ip: {tool1, tool2}}
        
        # Penalty tracking: {tool: penalty_score}
        self.penalties: Dict[str, Dict[str, int]] = {}  # {ip: {tool: penalty}}
        
        # Exclusion periods: {tool: iterations_remaining}
        self.exclusions: Dict[str, Dict[str, int]] = {}  # {ip: {tool: iterations}}
    
    def block_tool(self, ip: str, tool: str):
        """Mark a tool as blocked for this IP"""
        if ip not in self.session_blocked:
            self.session_blocked[ip] = set()
        self.session_blocked[ip].add(tool)
        
        # Add penalty
        if ip not in self.penalties:
            self.penalties[ip] = {}
        self.penalties[ip][tool] = self.penalties[ip].get(tool, 0) + 10
        
        debug_print(f"    [🚫 ToolBlocker] Blocked '{tool}' for {ip} (penalty: {self.penalties[ip][tool]})")
    
    def is_blocked(self, ip: str, tool: str) -> bool:
        """Check if tool is blocked"""
        # Check session blocked
        if ip in self.session_blocked and tool in self.session_blocked[ip]:
            return True
        
        # Check exclusions
        if ip in self.exclusions and tool in self.exclusions[ip]:
            if self.exclusions[ip][tool] > 0:
                return True
        
        return False
    
    def get_penalty(self, ip: str, tool: str) -> int:
        """Get penalty score for a tool"""
        if ip in self.penalties and tool in self.penalties[ip]:
            return self.penalties[ip][tool]
        return 0
    
    def record_suggestion(self, ip: str, tool: str):
        """Record that LLM suggested a tool (even if blocked)"""
        if ip not in self.penalties:
            self.penalties[ip] = {}
        
        # If tool was already blocked, increase penalty
        if self.is_blocked(ip, tool):
            self.penalties[ip][tool] = self.penalties[ip].get(tool, 0) + 5
            
            # If penalty >= 20 (suggested 2+ times), exclude for 3 iterations
            if self.penalties[ip][tool] >= 20:
                if ip not in self.exclusions:
                    self.exclusions[ip] = {}
                self.exclusions[ip][tool] = 3
                debug_print(f"    [🚫 ToolBlocker] Tool '{tool}' excluded for 3 iterations (penalty: {self.penalties[ip][tool]})")
    
    def decrement_exclusions(self, ip: str):
        """Decrement exclusion counters after each iteration"""
        if ip in self.exclusions:
            for tool in list(self.exclusions[ip].keys()):
                self.exclusions[ip][tool] -= 1
                if self.exclusions[ip][tool] <= 0:
                    del self.exclusions[ip][tool]
                    debug_print(f"    [✓ ToolBlocker] Tool '{tool}' exclusion expired for {ip}")
    
    def get_blocked_list(self, ip: str) -> List[str]:
        """Get list of blocked tools for an IP"""
        blocked = []
        
        # Session blocked
        if ip in self.session_blocked:
            blocked.extend(self.session_blocked[ip])
        
        # Excluded
        if ip in self.exclusions:
            blocked.extend([t for t, iters in self.exclusions[ip].items() if iters > 0])
        
        return list(set(blocked))


