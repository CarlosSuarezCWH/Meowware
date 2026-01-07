import subprocess
import shutil
from typing import Dict, Any
from .base import BaseTool
from ..core.exceptions import ToolError
from ..core.logger import debug_print

class NmapTool(BaseTool):
    @property
    def name(self) -> str:
        return "nmap"

    def run(self, target_ip: str, mode: str = "quick") -> str:
        """
        v17.5: Enhanced nmap with better service detection and OS detection.
        Modes: 'quick' (Top 1000 with -A), 'std' (Top 1000 with -A -O), 'full' (65535)
        """
        if not shutil.which("nmap"):
            raise ToolError("nmap is not installed or not in PATH.")

        profiles = {
            # v17.5: Improved quick mode - use top 1000 ports with service/OS detection
            "quick": ["-T4", "--top-ports", "1000", "-sV", "-sC", "-A", "--version-intensity", "5"],
            # v17.5: Standard mode with OS detection
            "std": ["-T4", "--top-ports", "1000", "-sV", "-sC", "-A", "-O", "--version-intensity", "6"],
            # v17.5: Full scan with all detection enabled
            "full": ["-T4", "-p-", "-sV", "-sC", "-A", "-O", "--version-intensity", "7"]
        }
        
        args = profiles.get(mode, profiles["quick"])
        cmd = ["nmap"] + args + ["-oX", "-", target_ip]
        
        try:
            # v17.5: Increased timeout for better detection
            timeout = 900 if mode == "full" else 300 if mode == "std" else 180
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            # v17.5: Validate nmap output
            if result.returncode != 0:
                debug_print(f"  [⚠] Nmap returned non-zero exit code: {result.returncode}")
                debug_print(f"  [⚠] Stderr: {result.stderr[:200]}")
            
            # v17.5: Check if output is valid XML
            if not result.stdout.strip() or "<nmaprun" not in result.stdout:
                debug_print(f"  [⚠] Nmap output appears invalid or empty")
                if result.stderr:
                    debug_print(f"  [⚠] Nmap stderr: {result.stderr[:300]}")
                raise ToolError(f"Nmap produced invalid output. Stderr: {result.stderr[:200]}")
            
            return result.stdout
        except subprocess.TimeoutExpired:
            raise ToolError(f"Nmap execution timed out after {timeout}s")
        except Exception as e:
            raise ToolError(f"Nmap execution failed: {e}")
