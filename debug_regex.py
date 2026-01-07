
import re

secret_patterns = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
}

js_content = """
    const apiKey = "AKIAABCDEFGHIJKLMNOP"; // Fake AWS Key (20 chars)
    const mapKey = "AIzaSyD-FakeGoogleKey123456789012345678"; // 39 chars total (AIza + 35)
"""

print(f"Content length: {len(js_content)}")

for name, pattern in secret_patterns.items():
    print(f"Testing {name} with pattern: {pattern}")
    matches = re.findall(pattern, js_content)
    print(f"Matches: {matches}")
