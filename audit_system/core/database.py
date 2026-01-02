"""
Database Persistence Layer
v16.2: SQLite database for scan history and analysis

Meowware - Developed by Carlos Mancera
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from ..core.models import ScanResult, Finding, Host
from ..core.debug import debug_print

class ScanDatabase:
    """SQLite database for storing scan history and enabling comparisons"""
    
    def __init__(self, db_path: str = ".meowware_db/scan_history.db"):
        """Initialize database connection"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
    
    def _init_schema(self):
        """Create database schema if not exists"""
        cursor = self.conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                duration_seconds INTEGER,
                total_hosts INTEGER,
                total_findings INTEGER,
                risk_level TEXT,
                metadata TEXT
            )
        """)
        
        # Hosts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                classification TEXT,
                services TEXT,
                tech_stack TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host_ip TEXT,
                title TEXT NOT NULL,
                category TEXT,
                severity TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                evidence TEXT,
                confidence_score REAL,
                cve_id TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        # Historical context for LLM
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS historical_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                finding_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                false_positive BOOLEAN DEFAULT 0,
                notes TEXT,
                UNIQUE(target, finding_hash)
            )
        """)
        
        # Indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_context_target ON historical_context(target)")
        
        self.conn.commit()
        debug_print(f"  [Database] Initialized at {self.db_path}")
    
    def save_scan(self, scan_result: ScanResult, duration_seconds: int = 0):
        """Save a complete scan result to database"""
        cursor = self.conn.cursor()
        
        # Calculate risk level
        critical = len([f for f in scan_result.findings if f.severity.value == "CRITICAL"])
        high = len([f for f in scan_result.findings if f.severity.value == "HIGH"])
        risk_level = "CRITICAL" if critical > 0 else ("HIGH" if high >= 3 else "MEDIUM")
        
        # Save scan
        cursor.execute("""
            INSERT INTO scans (id, target, timestamp, duration_seconds, total_hosts, total_findings, risk_level, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_result.id,
            scan_result.target.input,
            scan_result.timestamp,
            duration_seconds,
            len(scan_result.hosts),
            len(scan_result.findings),
            risk_level,
            json.dumps({
                "type": scan_result.target.type,
                "resolved_ips": scan_result.target.resolved_ips
            })
        ))
        
        # Save hosts
        for host in scan_result.hosts:
            services = json.dumps([{"port": s.port, "name": s.name, "state": s.state} for s in host.services])
            tech_stack = json.dumps(host.web_context.tech_stack if host.web_context else [])
            
            cursor.execute("""
                INSERT INTO hosts (scan_id, ip, hostname, classification, services, tech_stack)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_result.id,
                host.ip,
                host.hostname or "",
                host.classification.value if hasattr(host.classification, 'value') else str(host.classification),
                services,
                tech_stack
            ))
        
        # Save findings
        for finding in scan_result.findings:
            # Extract CVE ID if present
            cve_id = None
            if "CVE-" in finding.title:
                import re
                cve_match = re.search(r'CVE-\d{4}-\d+', finding.title)
                if cve_match:
                    cve_id = cve_match.group(0)
            
            # Extract host IP from title
            host_ip = None
            if "(" in finding.title and ")" in finding.title:
                import re
                ip_match = re.search(r'\(([0-9a-fA-F:.]+)\)', finding.title)
                if ip_match:
                    host_ip = ip_match.group(1)
            
            cursor.execute("""
                INSERT INTO findings (scan_id, host_ip, title, category, severity, description, recommendation, evidence, confidence_score, cve_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.id,
                host_ip,
                finding.title,
                finding.category,
                finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                finding.description,
                finding.recommendation,
                getattr(finding, 'raw_output', ''),
                getattr(finding, 'confidence_score', 0.5),
                cve_id
            ))
            
            # Update historical context
            self._update_historical_context(scan_result.target.input, finding)
        
        self.conn.commit()
        debug_print(f"  [Database] Saved scan {scan_result.id} with {len(scan_result.findings)} findings")
    
    def _update_historical_context(self, target: str, finding: Finding):
        """Update historical context for LLM decision making"""
        cursor = self.conn.cursor()
        
        # Create hash of finding (title + description key parts)
        import hashlib
        finding_key = f"{finding.title}:{finding.category}:{finding.severity}"
        finding_hash = hashlib.md5(finding_key.encode()).hexdigest()
        
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO historical_context (target, finding_hash, first_seen, last_seen, occurrence_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(target, finding_hash) DO UPDATE SET
                last_seen = ?,
                occurrence_count = occurrence_count + 1
        """, (target, finding_hash, now, now, now))
        
        self.conn.commit()
    
    def get_previous_findings(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get previous findings for a target to help LLM context"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT title, category, severity, occurrence_count, false_positive
            FROM historical_context hc
            JOIN findings f ON hc.finding_hash = (
                SELECT finding_hash FROM historical_context 
                WHERE target = ? AND title = f.title LIMIT 1
            )
            WHERE hc.target = ? AND hc.false_positive = 0
            ORDER BY hc.occurrence_count DESC, hc.last_seen DESC
            LIMIT ?
        """, (target, target, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def mark_false_positive(self, target: str, finding_title: str):
        """Mark a finding as false positive for future filtering"""
        cursor = self.conn.cursor()
        
        import hashlib
        finding_key = f"{finding_title}:"
        finding_hash = hashlib.md5(finding_key.encode()).hexdigest()
        
        cursor.execute("""
            UPDATE historical_context
            SET false_positive = 1
            WHERE target = ? AND finding_hash LIKE ?
        """, (target, finding_hash + "%"))
        
        self.conn.commit()
        debug_print(f"  [Database] Marked {finding_title} as false positive for {target}")
    
    def get_scan_comparison(self, target: str, scan_id_1: str, scan_id_2: str) -> Dict[str, Any]:
        """Compare two scans to identify changes"""
        cursor = self.conn.cursor()
        
        # Get findings from both scans
        cursor.execute("""
            SELECT title, severity, COUNT(*) as count
            FROM findings
            WHERE scan_id = ? OR scan_id = ?
            GROUP BY title, severity
        """, (scan_id_1, scan_id_2))
        
        findings = {}
        for row in cursor.fetchall():
            key = f"{row['title']}:{row['severity']}"
            findings[key] = row['count']
        
        # Identify new findings (in scan_id_2 but not in scan_id_1)
        cursor.execute("""
            SELECT title, severity, description
            FROM findings
            WHERE scan_id = ? AND (title, severity) NOT IN (
                SELECT title, severity FROM findings WHERE scan_id = ?
            )
        """, (scan_id_2, scan_id_1))
        
        new_findings = [dict(row) for row in cursor.fetchall()]
        
        # Identify resolved findings (in scan_id_1 but not in scan_id_2)
        cursor.execute("""
            SELECT title, severity, description
            FROM findings
            WHERE scan_id = ? AND (title, severity) NOT IN (
                SELECT title, severity FROM findings WHERE scan_id = ?
            )
        """, (scan_id_1, scan_id_2))
        
        resolved_findings = [dict(row) for row in cursor.fetchall()]
        
        return {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "total_new": len(new_findings),
            "total_resolved": len(resolved_findings)
        }
    
    def get_scan_history(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get scan history for a target"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, duration_seconds, total_hosts, total_findings, risk_level
            FROM scans
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (target, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def close(self):
        """Close database connection"""
        self.conn.close()



