import subprocess
import shutil
from typing import Any
from .base import BaseTool
from ..core.exceptions import ToolError

class WhoisTool(BaseTool):
    @property
    def name(self) -> str:
        return "whois"

    def run(self, domain: str) -> str:
        """
        Runs whois against the target domain.
        Returns the stdout text.
        """
        if not shutil.which("whois"):
            # Warning only? Or fail? The plan implies these are required.
            # But maybe whois isn't installed. We'll raise ToolError.
            raise ToolError("whois is not installed or not in PATH.")

        cmd = ["whois", domain]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            # Whois often returns non-zero exit codes even on success or partial success depending on the server
            # We return stdout regardless.
            return result.stdout
        except Exception as e:
            raise ToolError(f"Whois execution failed: {str(e)}")
