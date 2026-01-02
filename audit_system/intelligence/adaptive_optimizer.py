"""
Adaptive Optimization Engine
Automatically adjusts tool selection based on partial results

Meowware v16.0 - Developed by Carlos Mancera
"""
from typing import Dict, List, Any, Optional
from ..core.models import Finding, Severity
from ..core.debug import debug_print

class AdaptiveOptimizer:
    """
    Adapts tool selection and execution based on real-time results
    - If critical findings found → deepen scan
    - If WAF blocking → reduce aggressiveness
    - If no findings → optimize time
    """
    
    def __init__(self):
        self.partial_results = {}
        self.adaptation_history = []
    
    def analyze_partial_results(self, partial_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze partial scan results and suggest adaptations
        
        Args:
            partial_results: {
                "findings": List[Finding],
                "tools_executed": List[str],
                "waf_blocks": int,
                "time_elapsed": int,
                "critical_findings": int
            }
        
        Returns:
            Adaptation recommendations
        """
        adaptations = {
            "deepen_scan": False,
            "reduce_aggressiveness": False,
            "skip_tools": [],
            "add_tools": [],
            "reason": ""
        }
        
        findings = partial_results.get("findings", [])
        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        waf_blocks = partial_results.get("waf_blocks", 0)
        time_elapsed = partial_results.get("time_elapsed", 0)
        
        # Rule 1: If many critical findings, deepen scan
        if critical_count >= 3 or (critical_count >= 1 and high_count >= 5):
            adaptations["deepen_scan"] = True
            adaptations["add_tools"].extend(["nuclei", "deep_scan"])
            adaptations["reason"] = f"Found {critical_count} critical and {high_count} high findings - deepening scan"
            debug_print(f"  [Adaptive] Deepening scan due to critical findings")
        
        # Rule 2: If WAF blocking, reduce aggressiveness
        if waf_blocks >= 5:
            adaptations["reduce_aggressiveness"] = True
            adaptations["skip_tools"].extend(["feroxbuster", "sqlmap", "nuclei"])
            adaptations["reason"] = f"WAF blocking detected ({waf_blocks} blocks) - reducing aggressiveness"
            debug_print(f"  [Adaptive] Reducing aggressiveness due to WAF blocks")
        
        # Rule 3: If no findings after significant time, optimize
        if len(findings) == 0 and time_elapsed > 300:  # 5 minutes
            adaptations["skip_tools"].extend(["deep_scan", "comprehensive_scan"])
            adaptations["reason"] = "No findings after 5 minutes - optimizing scan time"
            debug_print(f"  [Adaptive] Optimizing scan - no findings detected")
        
        # Rule 4: If WordPress detected with vulnerabilities, focus on CMS
        wp_findings = [f for f in findings if "wordpress" in f.title.lower() or "wp" in f.title.lower()]
        if wp_findings and "wpscan" not in partial_results.get("tools_executed", []):
            adaptations["add_tools"].append("wpscan")
            adaptations["reason"] = "WordPress vulnerabilities detected - adding WPScan"
        
        return adaptations
    
    def adapt_tool_plan(self, original_plan: Dict[str, Any], 
                       adaptations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adapt original tool execution plan based on recommendations
        
        Args:
            original_plan: Original tool execution plan
            adaptations: Adaptation recommendations
        
        Returns:
            Adapted tool plan
        """
        # v16.1: Ensure original_plan is a dict before copying
        if not isinstance(original_plan, dict):
            original_plan = {}
        adapted_plan = original_plan.copy() if isinstance(original_plan, dict) else {}
        
        # Add tools if deepening scan
        if adaptations["deepen_scan"]:
            for tool in adaptations["add_tools"]:
                if tool not in adapted_plan.get("tools_to_run", {}):
                    adapted_plan["tools_to_run"][tool] = {
                        "tool": tool,
                        "reason": adaptations["reason"],
                        "priority": "high"
                    }
        
        # Remove tools if reducing aggressiveness
        if adaptations["reduce_aggressiveness"]:
            for tool in adaptations["skip_tools"]:
                if tool in adapted_plan.get("tools_to_run", {}):
                    del adapted_plan["tools_to_run"][tool]
                    debug_print(f"  [Adaptive] Skipping {tool} due to WAF blocks")
        
        # Mark tools as non-aggressive
        if adaptations["reduce_aggressiveness"]:
            for tool_config in adapted_plan.get("tools_to_run", {}).values():
                if "aggressive" in tool_config:
                    tool_config["aggressive"] = False
        
        return adapted_plan
    
    def should_stop_early(self, partial_results: Dict[str, Any], 
                         max_time: int = 1800) -> bool:
        """
        Determine if scan should stop early
        
        Returns:
            True if should stop, False otherwise
        """
        time_elapsed = partial_results.get("time_elapsed", 0)
        findings = partial_results.get("findings", [])
        critical_findings = len([f for f in findings if f.severity == Severity.CRITICAL])
        
        # Stop if exceeded max time
        if time_elapsed > max_time:
            return True
        
        # Don't stop if critical findings found (keep investigating)
        if critical_findings > 0:
            return False
        
        # Stop if no findings after reasonable time
        if len(findings) == 0 and time_elapsed > 600:  # 10 minutes
            return True
        
        return False
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get statistics on optimizations made"""
        return {
            "total_adaptations": len(self.adaptation_history),
            "deepened_scans": sum(1 for a in self.adaptation_history if a.get("deepen_scan")),
            "reduced_aggressiveness": sum(1 for a in self.adaptation_history if a.get("reduce_aggressiveness")),
            "early_stops": sum(1 for a in self.adaptation_history if a.get("early_stop"))
        }

