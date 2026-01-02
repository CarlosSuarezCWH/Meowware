from .base_agent import BaseAgent
from ...core.models import Host
from typing import Dict, Any
import json

class DefenseAgent(BaseAgent):
    def __init__(self, model: str = None):
        super().__init__("Defense", model)

    def run(self, host: Host, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Specialized reasoning for evasion and bypass simulation.
        """
        executed_tools = context.get('blocked_tools', [])
        history_str = "\n".join([f"- {t} \u2713 (BLOQUEADO)" for t in executed_tools])
        
        prompt = f"""### ROL: DefenseAgent (Evasion & WAF Bypass Expert)
Analiza las protecciones detectadas y sugiere técnicas de EVASIÓN o herramientas pasivas.

### ESTADO DEL OBJETIVO:
- Host: {host.hostname} ({host.ip})
- WAF Detectado: {host.web_context.waf_name if host.web_context else "Búsqueda pendiente"}
- Stack Tecnológico: {json.dumps(host.tech_stack)}

### HERRAMIENTAS BLOQUEADAS/YA USADAS:
{history_str if history_str else "- Ninguna"}

### ACCIONES RECOMENDADAS:
- whatweb: Para identificar el WAF pasivamente.
- dirsearch: Con delays altos si hay rate-limiting.
- nuclei: Usando tags de 'exposure' que son menos ruidosos.

### RESPUESTA (JSON):
{{
    "decision": {{
        "tool": "tool_name",
        "reason": "why this evasion step is chosen",
        "params": {{ "technique": "name_of_technique", "delay": 500 }}
    }},
    "evasion_analysis": {{
        "likelihood_of_bypass": 0.0-1.0,
        "protection_strength": "High/Medium/Low"
    }}
}}
"""
        
        response_text = self._call_llm(prompt)
        if response_text:
            try:
                return json.loads(self._clean_json(response_text))
            except:
                pass
        
        return {}
