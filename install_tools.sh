#!/bin/bash

# Meowware v16.0 - Tool Installation Script
# Developed by Carlos Mancera
# Installs all required security tools for comprehensive auditing

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║    MEOWWARE v16.0 - TOOL INSTALLER                     ║"
echo "║    Developed by Carlos Mancera                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Updating package list...${NC}"
apt-get update -qq

echo ""
echo -e "${YELLOW}[CORE TOOLS]${NC}"

# Nmap
if ! command -v nmap &> /dev/null; then
    echo -e "${GREEN}[+] Installing nmap...${NC}"
    apt-get install -y nmap
else
    echo -e "${GREEN}[✓] nmap already installed${NC}"
fi

# Dig (dnsutils)
if ! command -v dig &> /dev/null; then
    echo -e "${GREEN}[+] Installing dig (dnsutils)...${NC}"
    apt-get install -y dnsutils
else
    echo -e "${GREEN}[✓] dig already installed${NC}"
fi

# Whois
if ! command -v whois &> /dev/null; then
    echo -e "${GREEN}[+] Installing whois...${NC}"
    apt-get install -y whois
else
    echo -e "${GREEN}[✓] whois already installed${NC}"
fi

# WhatWeb
if ! command -v whatweb &> /dev/null; then
    echo -e "${GREEN}[+] Installing whatweb...${NC}"
    apt-get install -y whatweb
else
    echo -e "${GREEN}[✓] whatweb already installed${NC}"
fi

echo ""
echo -e "${YELLOW}[CMS SCANNERS]${NC}"

# WPScan (Ruby gem)
if ! command -v wpscan &> /dev/null; then
    echo -e "${GREEN}[+] Installing wpscan...${NC}"
    apt-get install -y ruby ruby-dev libcurl4-openssl-dev make gcc
    gem install wpscan
    
    echo -e "${YELLOW}[!] WPScan requires an API token for full functionality${NC}"
    echo -e "${YELLOW}    Get one free at: https://wpscan.com/api${NC}"
    echo -e "${YELLOW}    Then run: wpscan --api-token YOUR_TOKEN${NC}"
else
    echo -e "${GREEN}[✓] wpscan already installed${NC}"
fi

# Joomscan
if ! command -v joomscan &> /dev/null; then
    echo -e "${GREEN}[+] Installing joomscan...${NC}"
    apt-get install -y joomscan || {
        echo -e "${YELLOW}[!] joomscan not in repos, installing manually...${NC}"
        cd /opt
        git clone https://github.com/OWASP/joomscan.git
        cd joomscan
        perl joomscan.pl --update
        ln -s /opt/joomscan/joomscan.pl /usr/local/bin/joomscan
        chmod +x /usr/local/bin/joomscan
    }
else
    echo -e "${GREEN}[✓] joomscan already installed${NC}"
fi

# Droopescan (Python)
if ! command -v droopescan &> /dev/null; then
    echo -e "${GREEN}[+] Installing droopescan...${NC}"
    pip3 install droopescan
else
    echo -e "${GREEN}[✓] droopescan already installed${NC}"
fi

echo ""
echo -e "${YELLOW}[WEB VULNERABILITY SCANNERS]${NC}"

# Nikto
if ! command -v nikto &> /dev/null; then
    echo -e "${GREEN}[+] Installing nikto...${NC}"
    apt-get install -y nikto
else
    echo -e "${GREEN}[✓] nikto already installed${NC}"
fi

# TestSSL
if ! command -v testssl &> /dev/null && ! command -v testssl.sh &> /dev/null; then
    echo -e "${GREEN}[+] Installing testssl.sh...${NC}"
    cd /opt
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
    chmod +x /usr/local/bin/testssl.sh
else
    echo -e "${GREEN}[✓] testssl.sh already installed${NC}"
fi

# SQLMap
if ! command -v sqlmap &> /dev/null; then
    echo -e "${GREEN}[+] Installing sqlmap...${NC}"
    apt-get install -y sqlmap
else
    echo -e "${GREEN}[✓] sqlmap already installed${NC}"
fi

# Nuclei (Go)
if ! command -v nuclei &> /dev/null; then
    echo -e "${GREEN}[+] Installing nuclei...${NC}"
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        ln -s ~/go/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || true
    else
        echo -e "${YELLOW}[!] Go not installed. Install Go first, then run:${NC}"
        echo -e "${YELLOW}    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
    fi
else
    echo -e "${GREEN}[✓] nuclei already installed${NC}"
fi

echo ""
echo -e "${YELLOW}[DISCOVERY & RECONNAISSANCE]${NC}"

# Subfinder (Go)
if ! command -v subfinder &> /dev/null; then
    echo -e "${GREEN}[+] Installing subfinder...${NC}"
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        ln -s ~/go/bin/subfinder /usr/local/bin/subfinder 2>/dev/null || true
    else
        echo -e "${YELLOW}[!] Go required for subfinder${NC}"
    fi
else
    echo -e "${GREEN}[✓] subfinder already installed${NC}"
fi

# Amass
if ! command -v amass &> /dev/null; then
    echo -e "${GREEN}[+] Installing amass...${NC}"
    apt-get install -y amass || {
        echo -e "${YELLOW}[!] Installing amass from snap...${NC}"
        snap install amass
    }
else
    echo -e "${GREEN}[✓] amass already installed${NC}"
fi

# SSLScan
if ! command -v sslscan &> /dev/null; then
    echo -e "${GREEN}[+] Installing sslscan...${NC}"
    apt-get install -y sslscan
else
    echo -e "${GREEN}[✓] sslscan already installed${NC}"
fi

echo ""
echo -e "${YELLOW}[DIRECTORY BRUTE FORCE]${NC}"

# Dirsearch
if ! command -v dirsearch &> /dev/null; then
    echo -e "${GREEN}[+] Installing dirsearch...${NC}"
    cd /opt
    git clone https://github.com/maurosoria/dirsearch.git
    cd dirsearch
    pip3 install -r requirements.txt
    ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
    chmod +x /usr/local/bin/dirsearch
else
    echo -e "${GREEN}[✓] dirsearch already installed${NC}"
fi

# Feroxbuster
if ! command -v feroxbuster &> /dev/null; then
    echo -e "${GREEN}[+] Installing feroxbuster...${NC}"
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
    mv feroxbuster /usr/local/bin/
else
    echo -e "${GREEN}[✓] feroxbuster already installed${NC}"
fi

echo ""
echo -e "${YELLOW}[SPECIALIZED TOOLS]${NC}"

# Git-Dumper
if ! pip3 show git-dumper &> /dev/null; then
    echo -e "${GREEN}[+] Installing git-dumper...${NC}"
    pip3 install git-dumper
else
    echo -e "${GREEN}[✓] git-dumper already installed${NC}"
fi

# Subjack (Go)
if ! command -v subjack &> /dev/null; then
    echo -e "${GREEN}[+] Installing subjack...${NC}"
    if command -v go &> /dev/null; then
        go install github.com/haccer/subjack@latest
        ln -s ~/go/bin/subjack /usr/local/bin/subjack 2>/dev/null || true
    else
        echo -e "${YELLOW}[!] Go required for subjack${NC}"
    fi
else
    echo -e "${GREEN}[✓] subjack already installed${NC}"
fi

# Python dependencies for Meowware
echo ""
echo -e "${YELLOW}[PYTHON DEPENDENCIES]${NC}"
echo -e "${GREEN}[+] Installing Python packages...${NC}"
pip3 install requests beautifulsoup4 python-nmap dnspython urllib3

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            INSTALLATION COMPLETE!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[!] IMPORTANT NOTES:${NC}"
echo ""
echo -e "1. WPScan API Token:"
echo -e "   Get a free token at: https://wpscan.com/api"
echo -e "   Configure with: wpscan --update --api-token YOUR_TOKEN"
echo ""
echo -e "2. Nuclei Templates:"
echo -e "   Update with: nuclei -update-templates"
echo ""
echo -e "3. Go Tools:"
if ! command -v go &> /dev/null; then
    echo -e "   ${RED}Go is not installed. Some tools may be missing.${NC}"
    echo -e "   Install Go: apt install golang-go"
else
    echo -e "   ${GREEN}Go is installed. Make sure ~/go/bin is in your PATH${NC}"
fi
echo ""
echo -e "${GREEN}You can now run Meowware with:${NC}"
echo -e "  python3 main.py --target example.com"
echo ""
