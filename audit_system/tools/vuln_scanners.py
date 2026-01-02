import subprocess
import shutil
import json
import os
from typing import List, Dict, Any
from .base import BaseTool

class NucleiTool(BaseTool):
    @property
    def name(self) -> str:
        return "nuclei"

    def is_available(self) -> bool:
        import shutil
        import os
        if shutil.which("nuclei"): return True
        home_bin = f"{os.path.expanduser('~')}/go/bin/nuclei"
        return os.path.exists(home_bin)

    def run(self, target: str, technology: str = "", tags: List[str] = []) -> List[Dict[str, Any]]:
        """
        Runs Nuclei vulnerability scanner.
        Args:
            target: URL or Host.
            technology: Tech stack string to infer tags (e.g. "wordpress").
            tags: Specific tags list.
        Returns:
            List of findings/vulnerabilities.
        """
        if not self.is_available():
            return []
            
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            nuclei_path = f"{os.path.expanduser('~')}/go/bin/nuclei"

        # Build tags logic
        # v16.2: Ensure tags is a list before copying
        if isinstance(tags, str):
            run_tags = [tags] if tags else []
        elif isinstance(tags, list):
            run_tags = tags.copy()
        else:
            run_tags = []
        if technology:
            # Simple inference
            tech_lower = technology.lower()
            if "wordpress" in tech_lower: run_tags.append("wordpress")
            if "drupal" in tech_lower: run_tags.append("drupal")
            if "apache" in tech_lower: run_tags.append("apache")
            if "nginx" in tech_lower: run_tags.append("nginx")
            if "php" in tech_lower: run_tags.append("php")
            
        tags_arg = ",".join(run_tags) if run_tags else "cves,misconfig,tech" # default safe tags

        # Command: nuclei -u <target> -json -tags <tags> -silent
        cmd = [nuclei_path, "-u", target, "-json", "-silent"]
        if tags_arg:
            cmd.extend(["-tags", tags_arg])

        findings = []
        try:
            # Nuclei might take time.
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse JSON lines
            for line in process.stdout.splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    # Extract key info
                    finding = {
                        "name": data.get('info', {}).get('name', 'Unknown Vulnerability'),
                        "severity": data.get('info', {}).get('severity', 'info'),
                        "description": data.get('info', {}).get('description', ''),
                        "matcher_name": data.get('matcher-name', ''),
                        "host": data.get('host', '')
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    pass

        except Exception:
            pass
            
        return findings
