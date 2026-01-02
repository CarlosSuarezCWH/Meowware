import subprocess
import shutil
import json
import os
import tempfile
from typing import List, Dict, Any
from .base import BaseTool

class DirsearchTool(BaseTool):
    @property
    def name(self) -> str:
        return "dirsearch"
        
    def is_available(self) -> bool:
        import shutil
        return shutil.which(self.name) is not None

    def run(self, target: str) -> List[Dict[str, Any]]:
        """
        Runs dirsearch for directory brute forcing.
        Returns list of interesting paths (200, 301, 403).
        """
        if not shutil.which("dirsearch"):
             # Fallback check: is it in path as python script? for now assume 'dirsearch' binary
             return []
        
        # Use temp file for report
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # Command: dirsearch -u <target> --format=json -o <tmp> --quiet -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql,sql.gz,tar,tar.gz,txt,wad,zip
        # Minimal extensions for speed in MVP
        cmd = ["dirsearch", "-u", target, "--format=json", "-o", report_path, "--quiet", "-e", "php,html,js,json,txt,conf,bak,zip"]
        
        findings = []
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=900) # 5 min timeout
            
            # Read JSON
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    
                # Dirsearch JSON structure:
                # { "url": "...", "results": [ { "url": "...", "status": 200, "content-length": 123 } ] }
                
                results = data.get('results', [])
                for res in results:
                    status = res.get('status')
                    if status in [200, 301, 302, 403, 500]:
                        findings.append({
                            "path": res.get('path', ''),
                            "url": res.get('url', ''),
                            "status": status,
                            "content_length": res.get('content-length')
                        })
                
                os.remove(report_path)

        except Exception:
            pass
            
        return findings
