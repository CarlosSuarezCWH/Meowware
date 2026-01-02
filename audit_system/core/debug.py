import os
import sys

# ANSI Color Codes
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"

def is_debug():
    """Check if debug mode is enabled."""
    return os.environ.get('DEBUG_MODE', '0') == '1'

def debug_print(message, prefix="DEBUG"):
    """Print debug message with icons."""
    icon = f"[{C}ℹ{W}]"
    if "⚠️" in message or "warning" in message.lower(): icon = f"[{Y}⚠{W}]"
    elif "✖" in message or "failed" in message.lower() or "not found" in message.lower(): icon = f"[{R}✖{W}]"
    elif "✔" in message or "success" in message.lower() or "connected" in message.lower(): icon = f"[{G}✔{W}]"
    elif "AI" in prefix or "Meowware" in message: icon = f"[{B}🧠{W}]"
    
    if is_debug():
        print(f" {icon} {message}", file=sys.stderr)

def debug_section(title):
    """Print a professional debug section header."""
    if is_debug():
        print(f"\n{B}{'='*60}{W}", file=sys.stderr)
        print(f"{C}[MEOWWARE SECTION] {W}{title}", file=sys.stderr)
        print(f"{B}{'='*60}{W}", file=sys.stderr)

def debug_tool(tool_name, command):
    """Print tool execution details."""
    if is_debug():
        print(f"\n[TOOL] Executing: {tool_name}", file=sys.stderr)
        print(f"[TOOL] Command: {' '.join(command) if isinstance(command, list) else command}", file=sys.stderr)

def debug_ai_prompt(prompt):
    """Print AI prompt."""
    if is_debug():
        print(f"\n[AI] >>> PROMPT TO LLM >>>", file=sys.stderr)
        print(f"{prompt}", file=sys.stderr)
        print(f"[AI] <<< END PROMPT <<<", file=sys.stderr)

def debug_ai_response(response):
    """Print AI response."""
    if is_debug():
        print(f"\n[AI] >>> LLM RESPONSE >>>", file=sys.stderr)
        print(f"{response}", file=sys.stderr)
        print(f"[AI] <<< END RESPONSE <<<", file=sys.stderr)
