import os
import json
from datetime import datetime
from typing import Dict, Any, List
from ..core.debug import debug_print
from ..core.models import ScanResult

class HistoryManager:
    def __init__(self, history_dir: str = ".meow_history"):
        self.history_dir = history_dir
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)

    def _get_path(self, target: str) -> str:
        safe_name = target.replace("/", "_").replace(":", "_")
        return os.path.join(self.history_dir, f"{safe_name}.json")

    def save_scan(self, result: ScanResult):
        """Saves current scan state for future comparison."""
        target = result.target.input
        path = self._get_path(target)
        
        # Load previous if exists
        history = self.load_history(target)
        
        # Current snapshot
        snapshot = {
            "timestamp": result.timestamp,
            "hosts": {h.ip: {"hostname": h.hostname, "banners": [s.banner for s in h.services if s.banner]} for h in result.hosts},
            "subdomains": [h.hostname for h in result.hosts if h.hostname]
        }
        
        history.append(snapshot)
        # Keep only last 5 scans
        history = history[-5:]
        
        with open(path, "w") as f:
            json.dump(history, f, indent=2)

    def load_history(self, target: str) -> List[Dict[str, Any]]:
        path = self._get_path(target)
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return []

    def get_diff(self, result: ScanResult) -> List[str]:
        """Identifies changes between current scan and previous one."""
        history = self.load_history(result.target.input)
        if not history: return []
        
        last = history[-1]
        changes = []
        
        # Check for new subdomains
        current_subs = set([h.hostname for h in result.hosts if h.hostname])
        last_subs = set(last.get("subdomains", []))
        
        new_subs = current_subs - last_subs
        if new_subs:
            changes.append(f"NEW SUBDOMAINS: {', '.join(new_subs)}")
            
        retired_subs = last_subs - current_subs
        if retired_subs:
            changes.append(f"RETIRED SUBDOMAINS (Potential leftovers): {', '.join(retired_subs)}")

        # Check for banner changes
        for h in result.hosts:
             if h.ip in last.get("hosts", {}):
                 last_banners = set(last["hosts"][h.ip].get("banners", []))
                 curr_banners = set([s.banner for s in h.services if s.banner])
                 if curr_banners != last_banners:
                     changes.append(f"BANNER CHANGE on {h.ip}: {last_banners} -> {curr_banners}")

        return changes
