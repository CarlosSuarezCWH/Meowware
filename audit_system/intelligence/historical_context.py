"""
Historical Context for LLM Decision Making
v16.2: Provides historical context to reduce false positives

Meowware - Developed by Carlos Mancera
"""
from typing import List, Dict, Any, Optional
from ..core.database import ScanDatabase
from ..core.debug import debug_print

class HistoricalContext:
    """Provides historical context to LLM for better decision making"""
    
    def __init__(self, db: ScanDatabase):
        self.db = db
    
    def get_context_for_target(self, target: str) -> Dict[str, Any]:
        """
        Get historical context for a target to help LLM make better decisions
        
        Returns:
            Dictionary with previous findings, false positives, trends
        """
        previous_findings = self.db.get_previous_findings(target, limit=20)
        scan_history = self.db.get_scan_history(target, limit=5)
        
        # Analyze trends
        trends = self._analyze_trends(scan_history)
        
        # Extract common false positives
        false_positives = [f for f in previous_findings if f.get('false_positive', False)]
        
        context = {
            "previous_findings": previous_findings,
            "false_positives": false_positives,
            "scan_count": len(scan_history),
            "trends": trends,
            "common_issues": self._extract_common_issues(previous_findings)
        }
        
        debug_print(f"  [Historical Context] Loaded {len(previous_findings)} previous findings for {target}")
        return context
    
    def _analyze_trends(self, scan_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze trends in scan history"""
        if len(scan_history) < 2:
            return {"status": "insufficient_data"}
        
        # Compare latest vs previous
        latest = scan_history[0]
        previous = scan_history[1]
        
        findings_change = latest.get('total_findings', 0) - previous.get('total_findings', 0)
        risk_change = latest.get('risk_level') != previous.get('risk_level')
        
        return {
            "findings_trend": "increasing" if findings_change > 0 else ("decreasing" if findings_change < 0 else "stable"),
            "findings_delta": findings_change,
            "risk_changed": risk_change,
            "scans_analyzed": len(scan_history)
        }
    
    def _extract_common_issues(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract most common issues from historical findings"""
        from collections import Counter
        
        # Count occurrences
        issue_counts = Counter()
        for finding in findings:
            if not finding.get('false_positive', False):
                # Extract key part of title (before IP/hostname)
                title = finding.get('title', '')
                key_part = title.split('(')[0].strip() if '(' in title else title
                issue_counts[key_part] += finding.get('occurrence_count', 1)
        
        # Return top 5 most common
        return [issue for issue, count in issue_counts.most_common(5)]
    
    def filter_known_false_positives(self, new_findings: List, target: str) -> List:
        """Filter out findings that are known false positives"""
        previous = self.db.get_previous_findings(target, limit=100)
        false_positive_titles = {f['title'] for f in previous if f.get('false_positive', False)}
        
        filtered = []
        for finding in new_findings:
            # Check if this finding matches a known false positive
            finding_title = finding.title if hasattr(finding, 'title') else str(finding)
            if finding_title not in false_positive_titles:
                filtered.append(finding)
            else:
                debug_print(f"  [Historical Context] Filtered false positive: {finding_title}")
        
        return filtered
    
    def enrich_llm_prompt(self, target: str, base_prompt: str) -> str:
        """Enrich LLM prompt with historical context"""
        context = self.get_context_for_target(target)
        
        if context['scan_count'] == 0:
            return base_prompt  # No history available
        
        historical_section = f"""
        
[HISTORICAL CONTEXT - {target}]
Previous scans: {context['scan_count']}
Common issues found: {', '.join(context['common_issues'][:3]) if context['common_issues'] else 'None'}
Trend: {context['trends'].get('findings_trend', 'unknown')} ({context['trends'].get('findings_delta', 0)} findings change)

Known false positives (DO NOT report these):
{chr(10).join([f"- {fp['title']}" for fp in context['false_positives'][:5]]) if context['false_positives'] else "None"}

Focus on NEW findings not seen in previous scans.
"""
        
        return base_prompt + historical_section



