"""
Protocol-Specific Security Scanners (v11.0 Enhanced)

Specialized scanners for common network protocols to detect
misconfigurations and vulnerabilities with deep security checks.
"""

import subprocess
import shutil
import re
from typing import List, Dict, Any
from .base import BaseTool
from ..core.debug import debug_print

class MySQLScanner(BaseTool):
    @property
    def name(self) -> str:
        return "mysql_scanner"
    
    def is_available(self) -> bool:
        return shutil.which("nmap") is not None or shutil.which("mysql") is not None
    
    def run(self, host: str, port: int = 3306) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning MySQL on {host}:{port} [Deep Audit]...")
        
        # Level 1: Banner & Info (Nmap)
        if shutil.which("nmap"):
            try:
                cmd = ["nmap", "-p", str(port), "--script", "mysql-info,mysql-enum-users", host, "-oX", "-"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if "mysql-info" in res.stdout:
                    findings.append({
                        "issue": "MySQL Information Disclosure",
                        "severity": "LOW",
                        "description": "MySQL service exposes version and server capabilities in handshake."
                    })
            except: pass

        # Level 2: Connection & Auth Hardening
        try:
            import mysql.connector
            debug_print(f"  Attempting MySQL Security Verification...")
            # Check for anonymous/empty root
            try:
                conn = mysql.connector.connect(host=host, port=port, user='root', password='', connect_timeout=3)
                findings.append({
                    "issue": "CRITICAL: MySQL Anonymous Root Access",
                    "severity": "CRITICAL",
                    "description": "The server allows 'root' login with no password. Full database compromise possible.",
                    "recommendation": "Set a strong root password immediately."
                })
                conn.close()
            except mysql.connector.Error as e:
                if e.errno == 1045:
                    findings.append({
                        "issue": "MySQL Auth Policy: Password Required",
                        "severity": "INFO",
                        "description": "Standard authentication is enforced for 'root' user."
                    })
                elif "SSL connection error" in str(e):
                    findings.append({
                        "issue": "MySQL Encryption: TLS Recommended",
                        "severity": "MEDIUM",
                        "description": "Server refused connection or reported SSL error. Ensure TLS is enforced."
                    })

        except ImportError:
            debug_print("  mysql-connector not found, using baseline nmap checks.")
        except Exception as e:
             debug_print(f"  MySQL deep audit failed: {e}")
        
        return findings


class SMTPScanner(BaseTool):
    @property
    def name(self) -> str:
        return "smtp_scanner"
    
    def is_available(self) -> bool:
        return shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 25) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning SMTP on {host}:{port} [Compliance Check]...")
        
        if shutil.which("nmap"):
            try:
                cmd = [
                    "nmap", "-p", str(port),
                    "--script", "smtp-open-relay,smtp-enum-users,smtp-commands,smtp-ntlm-info",
                    host, "-oX", "-"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if "open relay" in result.stdout.lower():
                    findings.append({
                        "issue": "STORM-SMTP: Open Relay Detected",
                        "severity": "CRITICAL",
                        "description": "Server allows third-party mail relaying. High risk of being blacklisted for spam."
                    })
                
                if "STARTTLS" not in result.stdout:
                    findings.append({
                        "issue": "SMTP Cleartext Vulnerability",
                        "severity": "HIGH",
                        "description": "STARTTLS command not found in EHLO response. Email content may be intercepted."
                    })
                else:
                    findings.append({
                        "issue": "SMTP Encryption: STARTTLS Supported",
                        "severity": "INFO",
                        "description": "Server supports opportunistic TLS encryption."
                    })

                if "VRFY" in result.stdout or "EXPN" in result.stdout:
                    findings.append({
                        "issue": "SMTP Information Leak: User Enumeration",
                        "severity": "MEDIUM",
                        "description": "VRFY/EXPN commands enabled. Attackers can verify valid local email accounts."
                    })
                    
            except Exception as e:
                debug_print(f"SMTP deep audit failed: {e}")
        
        return findings

class SMTPEnumTool(BaseTool):
    @property
    def name(self) -> str:
        return "smtp-user-enum"
    
    def run(self, host: str, port: int = 25) -> List[Dict[str, Any]]:
        findings = []
        if not shutil.which("smtp-user-enum"): return findings
        
        debug_print(f"  Running SMTP User Enum on {host}:{port}...")
        try:
            # Check a few common users
            cmd = ["smtp-user-enum", "-M", "VRFY", "-u", "root,admin,postmaster", "-t", host, "-p", str(port)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if "exists" in res.stdout.lower():
                found = re.findall(r"(\w+)\s+exists", res.stdout, re.IGNORECASE)
                if found:
                    findings.append({
                        "issue": "SMTP User Information Disclosure",
                        "severity": "MEDIUM",
                        "description": f"Verified existence of local users: {', '.join(found)} via VRFY."
                    })
        except: pass
        return findings

class MySQLClientTool(BaseTool):
    @property
    def name(self) -> str:
        return "mysql-client"

    def is_available(self) -> bool:
        import shutil
        return shutil.which("mysql") is not None

    def run(self, host: str, port: int = 3306) -> List[Dict[str, Any]]:
        findings = []
        if not shutil.which("mysql"): return findings
        
        debug_print(f"  Attempting MySQL Client verify on {host}:{port}...")
        try:
            # Try anonymous connection
            cmd = ["mysql", "-h", host, "-P", str(port), "-u", "root", "-e", "status", "--connect-timeout=5"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                findings.append({
                    "issue": "MySQL Unauthenticated Access (Verified)",
                    "severity": "CRITICAL",
                    "description": "CRITICAL: Successfully connected to MySQL as root with no password using system client.",
                    "recommendation": "Firewall port 3306 and set strong password."
                })
        except: pass
        return findings

class SSHScanner(BaseTool):
    @property
    def name(self) -> str:
        return "ssh_scanner"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 22) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning SSH on {host}:{port} [Hardening Audit]...")
        
        if shutil.which("nmap"):
            try:
                cmd = [
                    "nmap", "-p", str(port),
                    "--script", "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey",
                    host, "-oX", "-"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Weak Algorithms
                weak_algos = ["arcfour", "3des", "md5", "sha1", "cbc", "diffie-hellman-group1-sha1"]
                detected_weak = []
                for algo in weak_algos:
                    if algo in result.stdout.lower():
                        detected_weak.append(algo)
                
                if detected_weak:
                    findings.append({
                        "issue": "SSH Weak Cryptography Support",
                        "severity": "MEDIUM",
                        "description": f"SSH server supports legacy/weak algorithms: {', '.join(detected_weak)}",
                        "recommendation": "Disable legacy KEX and Ciphers in sshd_config."
                    })

                # Auth Methods
                if "password" in result.stdout.lower() and "publickey" in result.stdout.lower():
                    findings.append({
                        "issue": "SSH Auth Policy: Password Allowed",
                        "severity": "LOW",
                        "description": "Server accepts password authentication. Key-based auth is recommended."
                    })
                elif "password" in result.stdout.lower():
                     findings.append({
                        "issue": "SSH Auth Policy: Password-Only",
                        "severity": "MEDIUM",
                        "description": "Only password authentication detected. Risk of brute-force attacks."
                    })
                
            except Exception as e:
                debug_print(f"SSH hardening check failed: {e}")
        
        return findings

class FTPScanner(BaseTool):
    @property
    def name(self) -> str:
        return "ftp_scanner"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 21) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning FTP on {host}:{port}...")
        if shutil.which("nmap"):
            try:
                cmd = ["nmap", "-p", str(port), "--script", "ftp-anon,ftp-bounce,ftp-syst", host, "-oX", "-"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if "Anonymous FTP login allowed" in result.stdout:
                    findings.append({
                        "issue": "HIGH: FTP Anonymous Access",
                        "severity": "HIGH",
                        "description": "Anonymous login is enabled. Sensitive files may be exposed."
                    })
            except: pass
        return findings

class RDPScanner(BaseTool):
    @property
    def name(self) -> str:
        return "rdp_scanner"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 3389) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning RDP on {host}:{port}...")
        if shutil.which("nmap"):
            try:
                cmd = ["nmap", "-p", str(port), "--script", "rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info", host, "-oX", "-"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if "VULNERABLE" in result.stdout:
                    findings.append({
                        "issue": "CRITICAL: RDP Remote Code Execution (MS12-020)",
                        "severity": "CRITICAL",
                        "description": "RDP service is vulnerable to legacy RCE exploits (BlueKeep/MS12-020)."
                    })
                if "NLA" not in result.stdout:
                     findings.append({
                        "issue": "RDP Hardening: NLA Disabled",
                        "severity": "MEDIUM",
                        "description": "Network Level Authentication (NLA) is disabled. Service is vulnerable to pre-auth RDP attacks."
                    })
            except: pass
        return findings
class SMBScanner(BaseTool):
    @property
    def name(self) -> str:
        return "smb_scanner"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None or shutil.which("smbclient") is not None
    
    def run(self, host: str, port: int = 445) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning SMB on {host}:{port}...")
        if shutil.which("nmap"):
            try:
                cmd = ["nmap", "-p", str(port), "--script", "smb-enum-shares,smb-security-mode,smb-os-discovery", host, "-oX", "-"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if "Anonymous login allowed" in res.stdout or "Guest login allowed" in res.stdout:
                    findings.append({
                        "issue": "HIGH: SMB Anonymous Access",
                        "severity": "HIGH",
                        "description": "SMB service allows anonymous or guest login. Potential for sensitive data leakage.",
                        "recommendation": "Disable guest access and require authentication."
                    })
                if "Message signing is disabled" in res.stdout:
                    findings.append({
                        "issue": "MEDIUM: SMB Message Signing Disabled",
                        "severity": "MEDIUM",
                        "description": "SMB signing is not enforced. Risk of NTLM relay attacks.",
                        "recommendation": "Enable 'Require Security Signature' in group policy."
                    })
            except: pass
        return findings

class LDAPScanner(BaseTool):
    @property
    def name(self) -> str:
        return "ldap_scanner"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 389) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning LDAP on {host}:{port}...")
        try:
            cmd = ["nmap", "-p", str(port), "--script", "ldap-rootdse,ldap-search", host, "-oX", "-"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "namingContexts" in res.stdout:
                findings.append({
                    "issue": "MEDIUM: LDAP Anonymous Bind",
                    "severity": "MEDIUM",
                    "description": "LDAP server allows anonymous binds. Information about directory structure can be leaked.",
                    "recommendation": "Disable anonymous binds in LDAP configuration."
                })
        except: pass
        return findings

class RPCScanner(BaseTool):
    @property
    def name(self) -> str:
        return "rpc_scanner"

    def is_available(self) -> bool:
        return shutil.which("rpcinfo") is not None
    
    def run(self, host: str, port: int = 111) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning RPC on {host}:{port}...")
        try:
            cmd = ["rpcinfo", "-p", host]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                services = re.findall(r"\d+\s+\d+\s+(tcp|udp)\s+\d+\s+(\w+)", res.stdout)
                if services:
                    findings.append({
                        "issue": "INFO: RPC Service Enumeration",
                        "severity": "INFO",
                        "description": f"Enumerated {len(services)} RPC services: {', '.join(set([s[1] for s in services]))}",
                        "recommendation": "Firewall RPC port 111 if not required externally."
                    })
        except: pass
        return findings

class SNMPScanner(BaseTool):
    @property
    def name(self) -> str:
        return "snmp_scanner"

    def is_available(self) -> bool:
        return shutil.which("snmp-check") is not None or shutil.which("nmap") is not None
    
    def run(self, host: str, port: int = 161) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"Scanning SNMP on {host}:{port}...")
        try:
            # Test default community strings
            for community in ["public", "private", "manager"]:
                cmd = ["nmap", "-sU", "-p", str(port), "--script", "snmp-brute", "--script-args", f"snmp-brute.communities={community}", host, "-oX", "-"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if community in res.stdout and "Valid community" in res.stdout:
                    findings.append({
                        "issue": f"CRITICAL: SNMP Default Community '{community}'",
                        "severity": "CRITICAL",
                        "description": f"SNMP service uses a well-known default community string: {community}",
                        "recommendation": "Change SNMP community strings to complex values."
                    })
                    break
        except: pass
        return findings
