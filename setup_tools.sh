#!/bin/bash
# Setup script for Neuronal Pentester v6.0

echo "[*] Setting up Neuronal Pentester tools..."

# 1. Add Go bin to PATH
echo "[+] Adding Go bin to PATH..."
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
fi
export PATH=$PATH:$HOME/go/bin

# 2. Install Dirsearch
echo "[+] Installing Dirsearch..."
if ! command -v dirsearch &> /dev/null; then
    sudo apt install dirsearch -y
fi

# 3. Verify Nuclei
echo "[+] Verifying Nuclei installation..."
if [ -f "$HOME/go/bin/nuclei" ]; then
    echo "[✓] Nuclei found at $HOME/go/bin/nuclei"
else
    echo "[!] Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

# 4. Install Ollama (optional but recommended)
echo "[+] Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "[!] Ollama not found. Install with:"
    echo "    curl -fsSL https://ollama.com/install.sh | sh"
    echo "    ollama pull llama2"
else
    echo "[✓] Ollama is installed"
fi

# 5. Verify all tools
echo ""
echo "[*] Tool Status:"
echo "  - Nmap: $(command -v nmap &> /dev/null && echo '✓' || echo '✗')"
echo "  - Whois: $(command -v whois &> /dev/null && echo '✓' || echo '✗')"
echo "  - Dig: $(command -v dig &> /dev/null && echo '✓' || echo '✗')"
echo "  - WhatWeb: $(command -v whatweb &> /dev/null && echo '✓' || echo '✗')"
echo "  - SSLScan: $(command -v sslscan &> /dev/null && echo '✓' || echo '✗')"
echo "  - Nuclei: $(command -v nuclei &> /dev/null && echo '✓' || echo '✗')"
echo "  - Dirsearch: $(command -v dirsearch &> /dev/null && echo '✓' || echo '✗')"
echo "  - Ollama: $(command -v ollama &> /dev/null && echo '✓' || echo '✗')"

echo ""
echo "[*] Setup complete! Reload your shell or run: source ~/.bashrc"
