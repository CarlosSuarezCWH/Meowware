"""
Pattern Learning System
Learns from scan history to optimize future scans

Meowware v16.0 - Developed by Carlos Mancera
"""
import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from ..core.models import ScanResult, Finding, Severity

class PatternLearner:
    """
    Learns patterns from scan history:
    - Which tools are most effective for each tech stack
    - Average scan duration by application type
    - False positive rate per tool
    - Most common vulnerabilities per stack
    """
    
    def __init__(self, learning_dir: str = ".meowware_learning"):
        self.learning_dir = Path(learning_dir)
        self.learning_dir.mkdir(exist_ok=True)
        self.patterns_file = self.learning_dir / "patterns.json"
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load learned patterns from disk"""
        if self.patterns_file.exists():
            try:
                with open(self.patterns_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            "tool_effectiveness": {},  # {"WordPress": {"wpscan": 0.95, "nikto": 0.3}}
            "scan_duration": {},      # {"WordPress": 450, "Custom": 1200}
            "false_positive_rate": {}, # {"nuclei": 0.15, "nikto": 0.25}
            "common_vulns": {},       # {"WordPress": ["XSS", "SQLi", "RCE"]}
            "tool_usage_count": {}    # {"wpscan": 150, "nikto": 200}
        }
    
    def _save_patterns(self):
        """Save learned patterns to disk"""
        try:
            with open(self.patterns_file, 'w') as f:
                json.dump(self.patterns, f, indent=2)
        except Exception:
            pass
    
    def learn_from_scan(self, scan_result: ScanResult, tools_used: List[str], 
                       duration_seconds: int, tech_stack: Dict[str, str]):
        """
        Learn from a completed scan
        
        Args:
            scan_result: Completed scan result
            tools_used: List of tools that were executed
            duration_seconds: How long the scan took
            tech_stack: Detected technologies
        """
        # Identify application type
        app_type = self._identify_app_type(scan_result, tech_stack)
        
        # Update tool effectiveness
        self._update_tool_effectiveness(app_type, tools_used, scan_result.findings)
        
        # Update scan duration
        self._update_scan_duration(app_type, duration_seconds)
        
        # Update common vulnerabilities
        self._update_common_vulns(app_type, scan_result.findings)
        
        # Update tool usage count
        for tool in tools_used:
            self.patterns["tool_usage_count"][tool] = \
                self.patterns["tool_usage_count"].get(tool, 0) + 1
        
        self._save_patterns()
    
    def _identify_app_type(self, scan_result: ScanResult, tech_stack: Dict[str, str]) -> str:
        """Identify application type from scan results"""
        # Check for CMS
        for host in scan_result.hosts:
            if host.web_context:
                cms = host.web_context.cms_detected
                if cms:
                    return cms
        
        # Check tech stack
        if "wordpress" in str(tech_stack).lower():
            return "WordPress"
        elif "joomla" in str(tech_stack).lower():
            return "Joomla"
        elif "drupal" in str(tech_stack).lower():
            return "Drupal"
        elif any(fw in str(tech_stack).lower() for fw in ["laravel", "django", "symfony"]):
            return "Framework"
        else:
            return "Custom"
    
    def _update_tool_effectiveness(self, app_type: str, tools_used: List[str], 
                                   findings: List[Finding]):
        """Update tool effectiveness scores"""
        if app_type not in self.patterns["tool_effectiveness"]:
            self.patterns["tool_effectiveness"][app_type] = {}
        
        # Count findings per tool (simplified - in real implementation, 
        # we'd track which tool found which finding)
        findings_count = len([f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]])
        
        for tool in tools_used:
            if tool not in self.patterns["tool_effectiveness"][app_type]:
                self.patterns["tool_effectiveness"][app_type][tool] = {
                    "score": 0.5,
                    "scans": 0,
                    "findings": 0
                }
            
            tool_data = self.patterns["tool_effectiveness"][app_type][tool]
            tool_data["scans"] += 1
            tool_data["findings"] += findings_count
            
            # Effectiveness = findings per scan (normalized)
            if tool_data["scans"] > 0:
                avg_findings = tool_data["findings"] / tool_data["scans"]
                # Normalize to 0-1 scale (assuming max 20 findings per scan)
                tool_data["score"] = min(avg_findings / 20.0, 1.0)
    
    def _update_scan_duration(self, app_type: str, duration_seconds: int):
        """Update average scan duration per app type"""
        if app_type not in self.patterns["scan_duration"]:
            self.patterns["scan_duration"][app_type] = {
                "total": 0,
                "count": 0,
                "average": 0
            }
        
        data = self.patterns["scan_duration"][app_type]
        data["total"] += duration_seconds
        data["count"] += 1
        data["average"] = data["total"] // data["count"]
    
    def _update_common_vulns(self, app_type: str, findings: List[Finding]):
        """Track most common vulnerabilities per app type"""
        if app_type not in self.patterns["common_vulns"]:
            self.patterns["common_vulns"][app_type] = defaultdict(int)
        
        for finding in findings:
            # Extract vulnerability type from title/category
            vuln_type = finding.category or "Unknown"
            # v16.1: Ensure the key exists before incrementing
            if vuln_type not in self.patterns["common_vulns"][app_type]:
                self.patterns["common_vulns"][app_type][vuln_type] = 0
            self.patterns["common_vulns"][app_type][vuln_type] += 1
    
    def recommend_tools(self, detected_stack: Dict[str, str], 
                       app_type: str = None) -> List[tuple]:
        """
        Recommend tools based on learned patterns
        
        Args:
            detected_stack: Detected technologies
            app_type: Application type (if known)
        
        Returns:
            List of (tool_name, confidence_score) tuples, sorted by effectiveness
        """
        if not app_type:
            app_type = self._identify_app_type_from_stack(detected_stack)
        
        if app_type not in self.patterns["tool_effectiveness"]:
            return []  # No patterns learned yet
        
        tool_scores = self.patterns["tool_effectiveness"][app_type]
        
        # Sort by effectiveness score
        recommendations = sorted(
            tool_scores.items(),
            key=lambda x: x[1]["score"],
            reverse=True
        )
        
        return [(tool, data["score"]) for tool, data in recommendations]
    
    def _identify_app_type_from_stack(self, stack: Dict[str, str]) -> str:
        """Identify app type from tech stack"""
        stack_str = str(stack).lower()
        
        if "wordpress" in stack_str:
            return "WordPress"
        elif "joomla" in stack_str:
            return "Joomla"
        elif "drupal" in stack_str:
            return "Drupal"
        elif any(fw in stack_str for fw in ["laravel", "django", "symfony"]):
            return "Framework"
        else:
            return "Custom"
    
    def get_expected_duration(self, app_type: str) -> Optional[int]:
        """Get expected scan duration for app type"""
        if app_type in self.patterns["scan_duration"]:
            return self.patterns["scan_duration"][app_type]["average"]
        return None
    
    def get_common_vulnerabilities(self, app_type: str, limit: int = 5) -> List[tuple]:
        """Get most common vulnerabilities for app type"""
        if app_type not in self.patterns["common_vulns"]:
            return []
        
        vulns = self.patterns["common_vulns"][app_type]
        sorted_vulns = sorted(vulns.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_vulns[:limit]

