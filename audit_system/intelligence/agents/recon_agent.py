from .base_agent import BaseAgent
from ...core.models import Host
from typing import Dict, Any
import json

class ReconAgent(BaseAgent):
    def __init__(self, model: str = None):
        super().__init__("Recon", model)

    def run(self, host: Host, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Specialized reasoning for reconnaissance and surface mapping.
        """
        executed_tools = context.get('history', [])
        history_str = "\n".join([f"- {t} \u2713 (YA USADO)" for t in executed_tools if t != "stop"])
        
        prompt = f"""### ROL: ReconAgent (Surface Mapping Expert)
Analiza el objetivo y sugiere la mejor herramienta de RECONOCIMIENTO.

### ESTADO DEL OBJETIVO:
- Host: {host.hostname} ({host.ip})
- Servicios: {json.dumps([s.name for s in host.services])}
- Anomalías: {json.dumps(context.get('anomalies', []))}

### HERRAMIENTAS EJECUTADAS (NO REPETIR):
{history_str if history_str else "- Ninguna"}

### ACCIONES RECOMENDADAS:
- whatweb: Si el stack web no está claro.
- dirsearch/feroxbuster: Para descubrir archivos ocultos.
- nmap_survey: Si faltan servicios por identificar.

### RESPUESTA (JSON):
{{
    "decision": {{
        "tool": "tool_name",
        "reason": "why this tool is chosen",
        "params": {{}}
    }},
    "intelligence": {{
        "surface_score": 0.0-1.0,
        "potential_vectors": ["list"],
        "is_recon_complete": false
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
