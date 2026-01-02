"""
Web Fuzzing & Directory Discovery Tools
"""

import subprocess
import shutil
import json
from typing import List, Dict, Any
from .base import BaseTool
from ..core.debug import debug_print

class WebFuzzerTool(BaseTool):
    @property
    def name(self) -> str:
        return "feroxbuster"

    def is_available(self) -> bool:
        import shutil
        return shutil.which(self.name) is not None

    def run(self, url: str, depth: int = 1, aggressive: bool = False, throttle: bool = False) -> List[Dict[str, Any]]:
        """
        Runs feroxbuster for fast recursive directory discovery.
        
        Args:
            url: Target URL
            depth: Recursion depth (default: 1)
            aggressive: If True, use deeper depth and more threads
            throttle: If True, use slower rate to avoid WAF blocking
        """
        findings = []
        if not shutil.which("feroxbuster"):
            debug_print("  ⚠️ feroxbuster not found. Skipping web fuzzing.")
            return findings

        # v16.3: Adjust depth and rate based on parameters
        if aggressive:
            depth = min(depth + 1, 3)  # Increase depth for aggressive mode
            debug_print(f"  Running feroxbuster on {url} (Depth: {depth}, Aggressive mode)...")
        elif throttle:
            debug_print(f"  Running feroxbuster on {url} (Depth: {depth}, Throttled mode for WAF)...")
        else:
            debug_print(f"  Running feroxbuster on {url} (Depth: {depth})...")
        
        try:
            # Use a common wordlist if available, otherwise feroxbuster uses its default
            cmd = [
                "feroxbuster", "--url", url, 
                "--depth", str(depth), 
                "--json", "--quiet", "--no-state", 
                "--timeout", "10"
            ]
            
            # v16.3: Adjust rate based on throttle parameter
            if throttle:
                cmd.extend(["--rate-limit", "5"])  # 5 requests per second (slower for WAF)
            elif aggressive:
                cmd.extend(["--threads", "50"])  # More threads for aggressive mode
            
            # Note: feroxbuster outputs one JSON per line
            timeout = 120 if throttle else (180 if aggressive else 60)
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = process.communicate(timeout=timeout)

            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    # We only care about successful or interesting status codes
                    if data.get('status') in [200, 204, 301, 302, 307, 403, 405]:
                        findings.append({
                            "path": data.get('url'),
                            "status": data.get('status'),
                            "content_length": data.get('content_length'),
                            "type": "directory" if data.get('url', '').endswith('/') else "file"
                        })
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
             debug_print(f"  ⚠️ feroxbuster timed out after {timeout}s.")
        except Exception as e:
            debug_print(f"  ⚠️ feroxbuster failed: {e}")

        return findings[:50] if aggressive else findings[:20]  # More results in aggressive mode
