import json
import os
from typing import Dict, Any, List
from datetime import datetime
from ..core.models import ScanResult, Severity, HostRole
from ..analysis.risk_scorer import RiskScorer, EnhancedRiskScorer

class DashboardReporter:
    """
    v1.0 'Tulipán': Dynamic & Interactive Security Dashboard.
    Generates a premium HTML/JS dashboard for remediation tracking.
    """
    
    @staticmethod
    def generate_dashboard(data: ScanResult) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # v18.5: Use the robust to_dict methods implemented in models
        findings_json = json.dumps([f.to_dict() for f in data.findings], default=str)
        hosts_json = json.dumps([h.to_dict() for h in data.hosts], default=str)
        
        # Risk Score calculation
        risk_data = EnhancedRiskScorer.calculate_comprehensive_risk(data.findings, data.hosts)
        overall_score = risk_data.get("overall_score", 0.0)
        
        # Logo SVG
        logo_svg = """
        <svg width="60" height="60" viewBox="0 0 60 60" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#8A2BE2;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#4B0082;stop-opacity:1" />
            </linearGradient>
            <linearGradient id="grad2" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#FF69B4;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#FF1493;stop-opacity:1" />
            </linearGradient>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
                <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                </feMerge>
            </filter>
        </defs>
        <rect width="60" height="60" fill="white"/>
        <g filter="url(#glow)">
            <!-- Cat Head -->
            <path d="M30 10 C 20 0, 10 10, 10 25 C 10 40, 20 50, 30 50 C 40 50, 50 40, 50 25 C 50 10, 40 0, 30 10 Z" fill="#FFFFFF"/>
            <!-- Ears -->
            <path d="M20 15 Q 15 5, 25 10 L 20 15 Z" fill="#E0BBE4"/>
            <path d="M40 15 Q 45 5, 35 10 L 40 15 Z" fill="#E0BBE4"/>
            <!-- Eyes -->
            <circle cx="24" cy="25" r="5" fill="#00F2FF"/>
            <circle cx="36" cy="25" r="5" fill="#00F2FF"/>
            <circle cx="24" cy="25" r="2" fill="#FFFFFF"/>
            <circle cx="36" cy="25" r="2" fill="#FFFFFF"/>
            <!-- Nose (Heart) -->
            <path d="M30 30 Q 28 28, 26 30 Q 28 32, 30 30 Q 32 32, 34 30 Q 32 28, 30 30 Z" fill="#ADD8E6"/>
            <!-- Tulip on Head -->
            <path d="M30 8 Q 28 2, 25 5 Q 27 10, 30 12 Q 33 10, 35 5 Q 32 2, 30 8 Z" fill="url(#grad1)"/>
            <path d="M30 8 Q 29 4, 28 6 Q 29 10, 30 12 Z" fill="url(#grad2)"/>
            <path d="M30 8 Q 31 4, 32 6 Q 31 10, 30 12 Z" fill="url(#grad2)"/>
            <!-- Leaves -->
            <path d="M15 35 Q 5 30, 10 45 Q 20 40, 15 35 Z" fill="#32CD32"/>
            <path d="M45 35 Q 55 30, 50 45 Q 40 40, 45 35 Z" fill="#32CD32"/>
            <!-- Heart Pendant -->
            <path d="M30 52 Q 28 50, 26 52 Q 28 54, 30 52 Q 32 54, 34 52 Q 32 50, 30 52 Z" fill="#ADD8E6"/>
        </g>
        </svg>
        """
        
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Meowware v1.0 'Tulipán' | Dashboard de Seguridad</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #050505;
            --glass-bg: rgba(20, 20, 25, 0.7);
            --accent-neon: #00f2ff;
            --accent-purple: #7000ff;
            --text-main: #e0e0e0;
            --text-dim: #a0a0a0;
            --sev-critical: #ff3333;
            --sev-high: #ff8800;
            --sev-medium: #ffcc00;
            --sev-low: #00cc66;
            --sev-info: #0099ff;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg-color);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            overflow-x: hidden;
        }}

        /* Background Animation */
        body::before {{
            content: '';
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle at 50% 50%, #101015 0%, #050505 100%);
            z-index: -1;
        }}

        .dashboard-container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            padding-bottom: 20px;
        }}

        .logo-box h1 {{
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -1px;
            background: linear-gradient(90deg, var(--accent-neon), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .scan-meta {{
            text-align: right;
            color: var(--text-dim);
            font-size: 0.9rem;
        }}

        /* Grid Layout */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}

        .glass-card {{
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            transition: transform 0.3s ease;
        }}

        .glass-card:hover {{
            transform: translateY(-5px);
            border-color: rgba(0, 242, 255, 0.2);
        }}

        /* Risk Score Meter */
        .score-display {{
            text-align: center;
            padding: 20px;
        }}

        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            border: 8px solid #222;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            position: relative;
            background: radial-gradient(circle, rgba(0,242,255,0.1) 0%, transparent 100%);
        }}

        .score-circle .number {{
            font-size: 3rem;
            font-weight: 700;
            color: var(--accent-neon);
        }}

        /* Findings Table */
        .findings-list {{
            margin-top: 40px;
        }}

        .finding-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            cursor: pointer;
            transition: background 0.2s ease;
        }}

        .finding-item:hover {{
            background: rgba(255,255,255,0.02);
        }}

        .sev-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .sev-CRITICAL {{ background: var(--sev-critical); color: #fff; }}
        .sev-HIGH {{ background: var(--sev-high); color: #fff; }}
        .sev-MEDIUM {{ background: var(--sev-medium); color: #000; }}
        .sev-LOW {{ background: var(--sev-low); color: #fff; }}
        .sev-INFO {{ background: var(--sev-info); color: #fff; }}
        
        .uncertainty-badge {{
            background: rgba(255, 100, 0, 0.1);
            border: 1px solid var(--sev-high);
            color: var(--sev-high);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            margin-left: 10px;
            font-weight: 600;
        }}

        /* Interactive Elements */
        .remediation-btn {{
            background: transparent;
            border: 1px solid var(--accent-neon);
            color: var(--accent-neon);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s;
        }}

        .remediation-btn:hover {{
            background: var(--accent-neon);
            color: #000;
        }}

        .remediated {{
            opacity: 0.5;
            text-decoration: line-through;
        }}

        /* Charts Section */
        .charts-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 40px;
        }}

        /* Mermaid Graph */
        .graph-container {{
            margin-top: 40px;
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 16px;
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <header>
            <div class="logo-box">
                <div style="display: flex; align-items: center; gap: 15px;">
                    <div style="width: 60px; height: 60px;">{logo_svg}</div>
                    <div>
                        <h1>ME<span style="color: var(--accent-purple);">O</span>WARE v1.0 "TULIPÁN"</h1>
                        <p style="font-size: 0.8rem; color: var(--text-dim);">Plataforma Profesional de Auditoría de Seguridad</p>
                    </div>
                </div>
            </div>
            <div class="scan-meta">
                <p>Objetivo: <b>{data.target.input}</b></p>
                <p>Generado: {timestamp}</p>
            </div>
        </header>

        <div class="dashboard-grid">
            <div class="glass-card">
                <h2>Resumen de Vulnerabilidades</h2>
                <div class="charts-row">
                    <canvas id="severityChart"></canvas>
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
            
            <div class="glass-card score-display">
                <h2>Postura de Riesgo</h2>
                <div class="score-circle">
                    <span class="number">{overall_score:.1f}</span>
                </div>
                <p style="color: var(--text-dim);">Puntuación de Salud de Seguridad</p>
                <div style="margin-top: 20px; text-align: left;">
                    <p><b>Hosts:</b> {len(data.hosts)}</p>
                    <p><b>Total de Hallazgos:</b> {len(data.findings)}</p>
                </div>
            </div>
        </div>

        <div class="glass-card findings-list">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Hallazgos y Seguimiento de Remediation</h2>
                <div class="filter-controls">
                    <!-- Filters could be added here -->
                </div>
            </div>
            <div id="findingsContainer">
                <!-- Javascript will populate this -->
            </div>
        </div>

        <div class="glass-card graph-container">
                <h2>Visualización de Ruta de Ataque (Descubrimiento MITRE)</h2>
            <div class="mermaid">
                graph LR
                    A["Reconnaissance"] --> B["Scanning"]
                    B --> C["Exploitation"]
                    C --> D["Compromise"]
                    style A fill:#1a1a1a,stroke:#00f2ff,stroke-width:2px,color:#fff
                    style B fill:#1a1a1a,stroke:#00f2ff,stroke-width:2px,color:#fff
                    style C fill:#1a1a1a,stroke:#ff3333,stroke-width:2px,color:#fff
                    style D fill:#7000ff,stroke:#7000ff,stroke-width:2px,color:#fff
            </div>
        </div>
    </div>

    <script>
        const findings = {findings_json};
        const hosts = {hosts_json};

        function renderFindings() {{
            const container = document.getElementById('findingsContainer');
            container.innerHTML = findings.map((f, index) => `
                <div class="finding-item" id="finding-${{index}}">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="sev-badge sev-${{f.severity}}">${{f.severity}}</span>
                        <div>
                            <p style="font-weight: 600;">
                                ${{f.title}}
                                ${{f.confidence_score < 0.6 ? '<span class="uncertainty-badge">VERIFICATION PENDING</span>' : ''}}
                            </p>
                            <p style="font-size: 0.8rem; color: var(--text-dim);">${{f.category}}</p>
                        </div>
                    </div>
                    <div>
                        <button class="remediation-btn" onclick="toggleRemediation(${{index}})">
                            Confirm Fix
                        </button>
                    </div>
                </div>
                <div id="details-${{index}}" style="display:none; padding: 20px; font-size: 0.9rem; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <p><b>Description:</b> ${{f.description}}</p>
                    <p style="margin-top: 10px;"><b>Remediation:</b> ${{f.recommendation}}</p>
                </div>
            `).join('');

            // Add click listeners for expansion
            findings.forEach((f, index) => {{
                document.getElementById(`finding-${{index}}`).addEventListener('click', (e) => {{
                   if(e.target.tagName !== 'BUTTON') {{
                        const details = document.getElementById(`details-${{index}}`);
                        details.style.display = details.style.display === 'none' ? 'block' : 'none';
                   }}
                }});
            }});
        }}

        function toggleRemediation(index) {{
            const item = document.getElementById(`finding-${{index}}`);
            item.classList.toggle('remediated');
            const btn = item.querySelector('button');
            btn.innerText = item.classList.contains('remediated') ? 'FIXED' : 'Confirm Fix';
        }}

        // Initialize Charts
        window.onload = () => {{
            renderFindings();
            
            // Severity Chart
            const sevCounts = findings.reduce((acc, f) => {{
                acc[f.severity] = (acc[f.severity] || 0) + 1;
                return acc;
            }}, {{}});

            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(sevCounts),
                    datasets: [{{
                        data: Object.values(sevCounts),
                        backgroundColor: ['#ff3333', '#ff8800', '#ffcc00', '#00cc66', '#0099ff'],
                        borderColor: 'transparent'
                    }}]
                }},
                options: {{
                    plugins: {{ legend: {{ position: 'right', labels: {{ color: '#fff' }} }} }}
                }}
            }});
            
            mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
        }};
    </script>
</body>
</html>
        """
        return html_template
