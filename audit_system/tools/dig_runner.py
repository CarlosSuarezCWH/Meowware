import subprocess
import shutil
from typing import Dict, Any
from .base import BaseTool
from ..core.exceptions import ToolError

class DigTool(BaseTool):
    @property
    def name(self) -> str:
        return "dig"

    def run(self, domain: str) -> Dict[str, str]:
        """
        Runs dig for multiple record types.
        Returns a dict: { 'A': 'output...', 'MX': 'output...' }
        """
        if not shutil.which("dig"):
            raise ToolError("dig is not installed (usually part of dnsutils/bind-utils).")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        results = {}

        for rtype in record_types:
            cmd = ["dig", "+short", rtype, domain]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                results[rtype] = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                results[rtype] = f"Error: {e.stderr}"
        
        return results
