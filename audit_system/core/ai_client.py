import json
import time
import os
from typing import List, Dict, Any, Optional
from .models import Host, Service
from .debug import debug_print, debug_ai_prompt, debug_ai_response
from ..intelligence.agents.recon_agent import ReconAgent
from ..intelligence.agents.exploit_agent import ExploitAgent
from ..intelligence.agents.defense_agent import DefenseAgent

class CognitiveEngine:
    def __init__(self, model: str = "deepseek-chat"):
        # v17.3: DeepSeek API support
        self.api_key = os.environ.get('DEEPSEEK_API_KEY', '')
        self.api_provider = os.environ.get('LLM_PROVIDER', 'deepseek').lower()  # 'deepseek' or 'ollama'
        
        if self.api_provider == 'deepseek':
            if not self.api_key:
                # v17.4: Don't disable immediately, check again later (might be loaded from .env)
                debug_print("  ⚠️ DEEPSEEK_API_KEY no configurada en CognitiveEngine.__init__")
                # Try to reload from environment
                self.api_key = os.environ.get('DEEPSEEK_API_KEY', '')
                if not self.api_key:
                    debug_print("  ⚠️ DEEPSEEK_API_KEY no configurada. Usando fallback heuristic.")
                    self.enabled = False
                    return
            self.api_url = "https://api.deepseek.com/v1/chat/completions"
            self.model = model if model != "llama2" else "deepseek-chat"
            debug_print(f"  [✓] DeepSeek API configurada: {self.model}")
        else:
            # Ollama (default legacy)
            self.api_url = os.environ.get('LLM_URL', "http://localhost:11434/api/generate")
            self.model = model
            debug_print(f"  [✓] Ollama configurado: {self.model}")
        
        self.enabled = True
        self.consecutive_failures = 0
        # v17.3: LLM Response Cache
        self.response_cache = {}  # Simple in-memory cache
        self.cache_hits = 0
        self.cache_misses = 0
        self._check_health()
        
        # v18.0: Multi-Agent Swarm
        self.recon_agent = ReconAgent(model=self.model)
        self.exploit_agent = ExploitAgent(model=self.model)
        self.defense_agent = DefenseAgent(model=self.model)

    def _check_health(self):
        """v17.3: Health check for LLM (DeepSeek or Ollama)."""
        if not self.enabled:
            return
        try:
            import requests
            if self.api_provider == 'deepseek':
                # DeepSeek: Just check if API key is set
                if not self.api_key:
                    debug_print("  [!] DeepSeek API: No API key. Fallback heuristic will be used.")
                    self.enabled = False
            else:
                # Ollama: Check local server
                requests.get("http://localhost:11434/", timeout=2)
        except:
            if self.api_provider == 'deepseek':
                debug_print("  [!] DeepSeek API: Health check skipped (API key configured)")
            else:
                debug_print("  [!] Ollama Health Check: OFFLINE. Fallback heuristic will be used.")

    def _delegate_to_agents(self, host: Host, context: str, history: List[str], findings_summary: str, iteration: int, anomalies: List[Any], hypotheses: List[Any], tech_stack: Dict[str, Any], recent_findings: List[Any]) -> Optional[Dict[str, Any]]:
        """v18.5: 3-Layer Decision Swarm."""
        
        # Build enhanced agent context
        agent_context = {
            "recent_findings": recent_findings or [],
            "findings_summary": findings_summary,
            "anomalies": anomalies or [],
            "hypotheses": hypotheses or [],
            "history": history,
            "blocked_tools": [tool for tool in history if "block" in tool.lower()],
            "tech_stack": tech_stack,
            "host_role": host.classification.value if hasattr(host, 'classification') else "UNKNOWN",
            "waf_detected": host.web_context.waf_detected if host.web_context else False
        }
        
        # Layer 1: HARD RULES (Direct Evidence)
        # If MySQL 3306 is open and not tested, prioritizing it via specialized logic
        
        # v1.0: Simplified decision flow - single authoritative voice
        # Layer 2: CONTEXTUAL STEERING
        # If we suspect a WAF or have been blocked, use defense strategy
        if agent_context["waf_detected"] or agent_context["blocked_tools"]:
            return self.defense_agent.run(host, agent_context)
            
        # If high/critical vulns found, use exploit strategy
        critical_vulns = [f for f in (recent_findings or []) if f.severity.name in ["CRITICAL", "HIGH"]]
        if critical_vulns:
            return self.exploit_agent.run(host, agent_context)
            
        # Layer 3: LLM REASONING (Default)
        return self.recon_agent.run(host, agent_context)

    def _call_llm_with_retry(self, prompt: str, retries: int = 3) -> Optional[str]:
        """v17.3: Call LLM (DeepSeek or Ollama) with exponential backoff retries."""
        import time
        import requests
        
        if not self.enabled:
            return None
        
        delay = 2 # Initial delay
        for i in range(retries):
            try:
                # v17.3: Solo mostrar intento si no es el primero o si falla
                if i > 0:
                    debug_print(f"  [AI Agent] Reintento {i+1}/{retries}...")
                
                # v17.3: DeepSeek API (OpenAI-compatible format)
                if self.api_provider == 'deepseek':
                    headers = {
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    }
                    payload = {
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a senior penetration tester. Always respond with valid JSON only."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.3,
                        "max_tokens": 2000
                    }
                    response = requests.post(self.api_url, json=payload, headers=headers, timeout=120)
                    
                    if response.status_code == 200:
                        self.consecutive_failures = 0
                        data = response.json()
                        # DeepSeek returns: {"choices": [{"message": {"content": "..."}}]}
                        content = data.get('choices', [{}])[0].get('message', {}).get('content', '{}')
                        return content
                    elif response.status_code == 401:
                        debug_print(f"  ⚠️ DeepSeek API: Invalid API key. Check DEEPSEEK_API_KEY environment variable.")
                        self.enabled = False
                        return None
                    else:
                        error_msg = response.json().get('error', {}).get('message', 'Unknown error')
                        debug_print(f"  ⚠️ DeepSeek API error {response.status_code}: {error_msg}. Retrying in {delay}s...")
                else:
                    # Ollama (legacy format)
                    response = requests.post(self.api_url, json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "keep_alive": "45m"
                    }, timeout=900)
                    
                    if response.status_code == 200:
                        self.consecutive_failures = 0
                        return response.json().get('response', '{}')
                    else:
                        debug_print(f"  ⚠️ Ollama error {response.status_code}. Retrying in {delay}s...")
                        
            except requests.exceptions.ReadTimeout:
                debug_print(f"  ⚠️ LLM Timeout. Retrying in {delay}s...")
            except requests.exceptions.RequestException as e:
                debug_print(f"  ⚠️ AI Connection error: {str(e)}. Retrying in {delay}s...")
            
            time.sleep(delay)
            delay *= 2 # Exponential backoff
        
        self.consecutive_failures += 1
        if self.consecutive_failures >= 3:
            debug_print("  [!] Circuit Breaker: Multiple AI failures. Reverting to Baseline Heuristics.")
            # We could disable self.enabled here but we keep it to allow future recovery
        return None

    def decide(self, host: Host, context: str, history: List[str] = None, findings_summary: str = "", iteration: int = 1, historical_context: Dict[str, Any] = None, anomalies: List[Any] = None, hypotheses: List[Any] = None, tech_stack: Dict[str, Any] = None, recent_findings: List[Any] = None, deep_dive_recommendations: List[str] = None, blocked_tools: List[str] = None) -> Dict[str, Any]:
        """
        Asks the LLM for a senior-level audit iteration decision.
        v16.4: Enhanced with pentester mindset, tech stack awareness, and deep dive recommendations.
        v17.3: Added fast path rules and caching.
        """
        debug_print(f"Iterative Audit Decision [Iter {iteration}] for host: {host.hostname}")
        history = history or []
        
        # v17.3: Fast Path - Decisiones automáticas sin LLM
        fast_decision = self._fast_path_decision(host, history, tech_stack, anomalies, deep_dive_recommendations)
        if fast_decision:
            tool_name = fast_decision.get('decision', {}).get('tool', 'unknown')
            reason = fast_decision.get('decision', {}).get('reason', '')
            debug_print(f"  [⚡ Fast Path] {tool_name} - {reason}")
            return fast_decision
        
        # v17.3: Check cache before calling LLM (solo si la herramienta sugerida no está ejecutada)
        cache_key = self._get_cache_key(host, history, tech_stack, anomalies)
        if cache_key in self.response_cache:
            cached_result = self.response_cache[cache_key]
            cached_tool = cached_result.get('decision', {}).get('tool', '')
            # v17.3: Validar que la herramienta cacheada no esté ya ejecutada
            if cached_tool and cached_tool not in history:
                self.cache_hits += 1
                debug_print(f"  [⚡ Cache] Reutilizando decisión: {cached_tool}")
                return cached_result
            else:
                # v17.3: Invalidar caché si la herramienta ya está ejecutada
                del self.response_cache[cache_key]
                debug_print(f"  [⚠] Caché invalidado: {cached_tool} ya ejecutado")
        self.cache_misses += 1
        
        if self.enabled:
            # v18.0: Multi-Agent Delegation
            agent_decision = self._delegate_to_agents(host, context, history, findings_summary, iteration, anomalies, hypotheses, tech_stack, recent_findings)
            if agent_decision:
                return agent_decision

            # Fallback to legacy single-prompt behavior if agents fail or return nothing
            prompt = self._build_prompt(host, context, history, findings_summary, iteration, historical_context, anomalies, hypotheses, tech_stack, recent_findings, deep_dive_recommendations)
            debug_ai_prompt(prompt)
            
            ai_text = self._call_llm_with_retry(prompt)
            if ai_text:
                try:
                    debug_ai_response(ai_text)
                    
                    # v17.4: Clean JSON from markdown code blocks (DeepSeek sometimes wraps JSON)
                    cleaned_text = ai_text.strip()
                    # Remove markdown code blocks if present
                    if '```json' in cleaned_text or (cleaned_text.startswith('```') and 'json' in cleaned_text[:20]):
                        # Find the JSON block - handle both ```json and ``` formats
                        lines = cleaned_text.split('\n')
                        json_lines = []
                        in_json_block = False
                        for line in lines:
                            stripped = line.strip()
                            # Start of code block
                            if stripped.startswith('```json') or (stripped.startswith('```') and not in_json_block):
                                in_json_block = True
                                continue
                            # End of code block
                            if in_json_block and stripped == '```':
                                break
                            # Content inside code block
                            if in_json_block:
                                json_lines.append(line)
                        cleaned_text = '\n'.join(json_lines).strip()
                    # Also handle case where JSON is wrapped but no ```json tag
                    elif cleaned_text.startswith('```') and cleaned_text.endswith('```'):
                        # Simple case: just remove first and last ```
                        cleaned_text = cleaned_text[3:-3].strip()
                    
                    result = json.loads(cleaned_text)
                    
                    # v17.4: Validate result structure
                    if not isinstance(result, dict):
                        raise ValueError("Response is not a dictionary")
                    
                    # Ensure decision field exists
                    if 'decision' not in result:
                        result['decision'] = {}
                    
                    # v17.3: Traceability mejorado
                    thought = result.get('thought', result.get('analyst_insight', ''))
                    if thought and thought != 'No explicit reasoning provided.':
                        debug_print(f"  [💭 Razonamiento]: {thought[:100]}")
                    
                    # v17.3: Cache successful response (solo si la herramienta no está ya ejecutada)
                    # Validar que la herramienta sugerida no esté en el historial antes de cachear
                    suggested_tool = result.get('decision', {}).get('tool', '')
                    if suggested_tool and suggested_tool != "stop":
                        # Solo cachear si la decisión es válida (no será rechazada)
                        self.response_cache[cache_key] = result
                        # Limit cache size to 100 entries
                        if len(self.response_cache) > 100:
                            # Remove oldest entry (simple FIFO)
                            oldest_key = next(iter(self.response_cache))
                            del self.response_cache[oldest_key]
                    
                    return result
                except (json.JSONDecodeError, ValueError) as e:
                    debug_print(f"  ⚠️ AI returned invalid JSON: {str(e)[:100]}. Falling back.")
        
        # v17.4: Pass tech_stack and findings to fallback for intelligent profile selection
        return self._heuristic_fallback(host, history, tech_stack, recent_findings)
    
    def _fast_path_decision(self, host: Host, history: List[str], tech_stack: Dict[str, Any], 
                           anomalies: List[Any], deep_dive_recommendations: List[str]) -> Optional[Dict[str, Any]]:
        """v17.3: Fast path - decisiones automáticas sin LLM para casos obvios"""
        import hashlib
        
        # Regla 1: MySQL expuesto públicamente → mysql-client (CRÍTICO)
        mysql_exposed = any(
            s.port == 3306 and s.state == 'open' and 'mysql' in s.name.lower()
            for s in host.services
        )
        if mysql_exposed and "mysql-client" not in history:
            return {
                "decision": {"tool": "mysql-client", "reason": "MySQL exposed publicly - CRITICAL"},
                "stop": False
            }
        
        # Regla 2: WordPress detectado → wpscan (si no ejecutado)
        if tech_stack and tech_stack.get('cms', ''):
            cms_lower = str(tech_stack.get('cms', '')).lower()
            if "wordpress" in cms_lower and "wpscan" not in history:
                return {
                    "decision": {"tool": "wpscan", "reason": "WordPress detected - enumerate plugins/themes"},
                    "stop": False
                }
        
        # Regla 3: Mail server → smtp-user-enum (si SMTP abierto y no ejecutado)
        if host.hostname and ("mail" in host.hostname.lower() or "smtp" in host.hostname.lower()):
            smtp_open = any(s.port in [25, 587, 465] and s.state == 'open' for s in host.services)
            if smtp_open and "smtp-user-enum" not in history:
                return {
                    "decision": {"tool": "smtp-user-enum", "reason": "Mail server with SMTP - enumerate users"},
                    "stop": False
                }
        
        # Regla 4: SQL Injection encontrado → sqlmap (si no ejecutado)
        sql_injection_found = any(
            "sql injection" in str(f.title).lower() or "sqli" in str(f.title).lower()
            for f in (getattr(host, 'findings', []) or [])
        )
        if sql_injection_found and "sqlmap" not in history and host.web_context:
            return {
                "decision": {"tool": "sqlmap", "reason": "SQL Injection detected - exploit with SQLMap"},
                "stop": False
            }
        
        # Regla 5: Deep dive recomienda herramienta crítica → ejecutar
        if deep_dive_recommendations:
            critical_tools = ["mysql-client", "sqlmap", "wpscan"]
            for tool in deep_dive_recommendations:
                if tool in critical_tools and tool not in history:
                    return {
                        "decision": {"tool": tool, "reason": f"Deep dive recommends {tool}"},
                        "stop": False
                    }
        
        return None
    
    def _get_cache_key(self, host: Host, history: List[str], tech_stack: Dict[str, Any], 
                      anomalies: List[Any]) -> str:
        """v17.3: Generate cache key for LLM responses"""
        import hashlib
        
        # Create hash from relevant context
        services_hash = hashlib.md5(
            str(sorted([f"{s.port}/{s.name}" for s in host.services if s.state == 'open'])).encode()
        ).hexdigest()[:8]
        
        tech_hash = hashlib.md5(
            str(tech_stack or {}).encode()
        ).hexdigest()[:8]
        
        history_str = ",".join(sorted(history[-5:]))  # Last 5 tools
        history_hash = hashlib.md5(history_str.encode()).hexdigest()[:8]
        
        anomalies_count = len(anomalies) if anomalies else 0
        
        return f"{host.ip}_{services_hash}_{tech_hash}_{history_hash}_{anomalies_count}"

    def _build_prompt(self, host: Host, context: str, history: List[str], findings: str, iteration: int, historical_context: Dict[str, Any] = None, anomalies: List[Any] = None, hypotheses: List[Any] = None, tech_stack: Dict[str, Any] = None, recent_findings: List[Any] = None, deep_dive_recommendations: List[str] = None) -> str:
        # v17.5: Enhanced services string - include ALL detected services with state
        # Prioritize open ports but also show filtered/closed for context
        open_services = [s for s in host.services if s.state == 'open']
        other_services = [s for s in host.services if s.state in ['filtered', 'closed'] and s.port in [25, 53, 80, 443, 3306, 5432, 22, 3389, 445]]
        
        # Build comprehensive services string
        services_parts = []
        for s in open_services:
            service_info = f"{s.port}/{s.name}"
            if s.product:
                service_info += f" ({s.product}"
                if s.version:
                    service_info += f" {s.version}"
                service_info += ")"
            services_parts.append(service_info)
        
        # Add filtered/closed important ports for context
        for s in other_services[:5]:  # Limit to top 5
            services_parts.append(f"{s.port}/{s.name} [{s.state}]")
        
        services_str = ", ".join(services_parts) if services_parts else "None detected"
        
        # v17.5: Enhanced history string with more context
        history_str = ", ".join(history) if history else "Initial discovery."
        
        # v16.2: Add historical context if available
        historical_section = ""
        if historical_context:
            false_positives = historical_context.get('false_positives', [])
            common_issues = historical_context.get('common_issues', [])
            
            if false_positives or common_issues:
                historical_section = f"""
        
[HISTORICAL CONTEXT]
Known false positives (DO NOT report): {', '.join([fp.get('title', '')[:50] for fp in false_positives[:3]]) if false_positives else 'None'}
Common issues in previous scans: {', '.join(common_issues[:3]) if common_issues else 'None'}
Focus on NEW findings not seen before.
"""
        
        infra_context = ""
        if hasattr(host, 'infrastructure_insights') and host.infrastructure_insights:
             infra_context = "\n- ".join(host.infrastructure_insights)
        
        # v16.3: Anomaly and Hypothesis Section
        anomaly_section = ""
        if anomalies:
            anomaly_descriptions = []
            for anomaly in anomalies[:5]:  # Top 5 anomalies
                anomaly_descriptions.append(f"  - {anomaly.type.value.upper()}: {anomaly.description[:100]} (Confidence: {anomaly.confidence:.0%})")
            anomaly_section = f"""
[ANOMALIES DETECTED - Something smells wrong]
{chr(10).join(anomaly_descriptions)}

These anomalies suggest potential security issues. Follow the clues:
"""
        
        hypothesis_section = ""
        if hypotheses:
            hyp_descriptions = []
            for hyp in hypotheses[:3]:  # Top 3 hypotheses
                hyp_descriptions.append(f"  - HYPOTHESIS: {hyp.title} (Confidence: {hyp.confidence:.0%})")
                hyp_descriptions.append(f"    Recommended tools: {', '.join(hyp.recommended_tools[:3])}")
            hypothesis_section = f"""
[ACTIVE HYPOTHESES - What we're investigating]
{chr(10).join(hyp_descriptions)}

These are our current theories. Use tools to confirm or reject them.
"""
        
        # v16.4: Tech Stack Section - v17.1: Always show, even if empty
        tech_stack_section = ""
        os_info = 'Unknown'
        web_server = ''
        database = ''
        cms = ''
        programming_lang = ''
        
        if tech_stack:
            os_info = tech_stack.get('os', 'Unknown')
            # Handle OperatingSystem enum
            if hasattr(os_info, 'value'):
                os_info = os_info.value
            web_server = tech_stack.get('web_server', '')
            database = tech_stack.get('database', '')
            cms = tech_stack.get('cms', '')
            programming_lang = tech_stack.get('programming_language', '')
        
        # v17.5: Detect context based on ACTUAL services, not just hostname
        context_note = ""
        detected_roles = []
        
        # Check for mail services (ports 25, 587, 465, 110, 143, 993, 995)
        mail_ports = [25, 587, 465, 110, 143, 993, 995]
        has_mail = any(s.port in mail_ports and s.state == 'open' for s in host.services)
        if has_mail:
            detected_roles.append("MAIL")
            context_note += "\n**CONTEXT: MAIL SERVER DETECTED** (ports 25/587/465/110/143 detected) - Prioritize SMTP, IMAP, POP3 security checks, user enumeration, and email-related vulnerabilities.\n"
        
        # Check for web services (ports 80, 443, 8080, 8443)
        web_ports = [80, 443, 8080, 8443]
        has_web = any(s.port in web_ports and s.state == 'open' for s in host.services)
        if has_web:
            detected_roles.append("WEB")
            if not context_note:  # Only add if not already mail server
                context_note += "\n**CONTEXT: WEB SERVER DETECTED** (ports 80/443 detected) - Prioritize web application security, directory enumeration, and web vulnerabilities.\n"
            else:
                context_note = context_note.replace("MAIL SERVER DETECTED", "MULTI-SERVICE (MAIL + WEB)")
        
        # Check for database services
        db_ports = [3306, 5432, 27017, 6379, 9200, 1433]
        has_db = any(s.port in db_ports and s.state == 'open' for s in host.services)
        if has_db:
            detected_roles.append("DATABASE")
            if context_note:
                context_note = context_note.replace("DETECTED", "DETECTED + DATABASE")
            else:
                context_note += "\n**CONTEXT: DATABASE SERVER DETECTED** - Prioritize database security checks, authentication bypass, and data exposure.\n"
        
        # Always show tech stack section, even if all are "Not detected"
        tech_stack_section = f"""
[TECHNOLOGY STACK DETECTED]
- Operating System: {os_info if os_info != 'Unknown' else 'Not detected'}
- Web Server: {web_server if web_server else 'Not detected'}
- Database: {database if database else 'Not detected'}
- CMS: {cms if cms else 'Not detected'}
- Programming Language: {programming_lang if programming_lang else 'Not detected'}
{context_note}
ADAPT YOUR AUDIT STRATEGY:
"""
        if os_info and os_info != 'Unknown':
            if "Windows" in str(os_info):
                tech_stack_section += "- Windows detected: Prioritize RDP (3389), SMB (445), IIS, MSSQL audits\n"
            elif "Linux" in str(os_info):
                tech_stack_section += "- Linux detected: Prioritize SSH (22), Apache/Nginx, MySQL/PostgreSQL audits\n"
        
        if cms:
            cms_lower = str(cms).lower()
            if "wordpress" in cms_lower:
                tech_stack_section += "- WordPress detected: Deep audit required - plugins, themes, users, database\n"
            elif "joomla" in cms_lower:
                tech_stack_section += "- Joomla detected: Component vulnerabilities, configuration files\n"
            elif "drupal" in cms_lower:
                tech_stack_section += "- Drupal detected: Module vulnerabilities, configuration exposure\n"
        
        if database:
            tech_stack_section += f"- {database} detected: Check for exposed database, weak authentication, SQL injection vectors\n"
        
        # v16.4: Recent Findings & Deep Dive Section
        # v17.5: Handle both Finding objects and dicts
        deep_dive_section = ""
        if recent_findings:
            recent_desc = []
            for f in recent_findings[:3]:  # Top 3 recent findings
                # Handle both Finding objects and dicts
                if isinstance(f, dict):
                    title = f.get('title', 'Unknown')[:80]
                    severity = f.get('severity', 'UNKNOWN')
                else:
                    title = f.title[:80] if hasattr(f, 'title') else str(f)[:80]
                    severity = f.severity.value if hasattr(f, 'severity') and hasattr(f.severity, 'value') else str(getattr(f, 'severity', 'UNKNOWN'))
                recent_desc.append(f"  - {title} (Severity: {severity})")
            deep_dive_section = f"""
[RECENT VULNERABILITIES FOUND - INVESTIGATE DEEPLY]
{chr(10).join(recent_desc)}

When vulnerabilities are found, you MUST investigate them deeply:
1. Search for related CVEs
2. Check for exploitability
3. Identify attack vectors
4. Follow the chain: "If X is vulnerable, what else can I exploit?"
"""
        
        if deep_dive_recommendations:
            deep_dive_section += f"""
[DEEP DIVE RECOMMENDATIONS]
Based on recent findings, these tools are recommended for deeper investigation:
{chr(10).join([f"  - {tool}" for tool in deep_dive_recommendations[:5]])}

PRIORITIZE these tools to investigate the vulnerabilities found.
"""
        
        # v17.2: Contextual Expert Knowledge - Only include relevant tech
        expert_rag = self._build_contextual_knowledge(tech_stack, host, services_str)

        # v17.5: Build concise, contextual prompt with history for blocking
        prompt = self._build_concise_prompt(
            host, iteration, services_str, history_str, findings,
            expert_rag, tech_stack_section, anomaly_section, 
            hypothesis_section, deep_dive_section, deep_dive_recommendations, history
        )
        
        return prompt
    
    def _build_contextual_knowledge(self, tech_stack: Dict[str, Any], host: Host, services_str: str) -> str:
        """v17.2: Build contextual expert knowledge - only include relevant tech"""
        knowledge = []
        
        # Only include knowledge for detected technologies
        if tech_stack:
            os_info = tech_stack.get('os', 'Unknown')
            if hasattr(os_info, 'value'):
                os_info = os_info.value
            
            web_server = tech_stack.get('web_server', '')
            database = tech_stack.get('database', '')
            cms = tech_stack.get('cms', '')
            programming_lang = tech_stack.get('programming_language', '')
            
            # OS-specific
            if "Windows" in str(os_info):
                knowledge.append("Windows: Check RDP(3389), SMB(445), IIS, MSSQL. Tags: 'windows','iis','cve'")
            elif "Linux" in str(os_info):
                knowledge.append("Linux: Check SSH(22), web servers, databases. Tags: 'linux','apache','nginx','cve'")
            
            # CMS-specific
            if cms:
                cms_lower = str(cms).lower()
                if "wordpress" in cms_lower:
                    knowledge.append("WordPress: Audit plugins/themes/users. Use wpscan. Tags: 'wordpress','cve'")
                elif "joomla" in cms_lower:
                    knowledge.append("Joomla: Check components/config. Tags: 'joomla','cve'")
                elif "drupal" in cms_lower:
                    knowledge.append("Drupal: Check modules/config. Tags: 'drupal','cve'")
            
            # Database-specific
            if database:
                db_lower = str(database).lower()
                if "mysql" in db_lower:
                    knowledge.append("MySQL: CRITICAL if exposed publicly. Check weak auth. Tags: 'mysql','exposure'")
                elif "postgres" in db_lower:
                    knowledge.append("PostgreSQL: Check auth bypass. Tags: 'postgres','exposure'")
                elif "mongo" in db_lower:
                    knowledge.append("MongoDB: Often unauthenticated. Tags: 'mongodb','exposure'")
                elif "redis" in db_lower:
                    knowledge.append("Redis: Often unauthenticated, RCE risk. Tags: 'redis','exposure'")
            
            # Web server-specific
            if web_server:
                ws_lower = str(web_server).lower()
                if "apache" in ws_lower:
                    knowledge.append("Apache: Check version CVEs. Tags: 'apache','cve'")
                elif "nginx" in ws_lower:
                    knowledge.append("Nginx: Check version CVEs. Tags: 'nginx','cve'")
                elif "iis" in ws_lower:
                    knowledge.append("IIS: Check Windows-specific CVEs. Tags: 'iis','windows','cve'")
        
        # Check services for additional context
        if "smtp" in services_str.lower() or "mail" in (host.hostname or "").lower():
            knowledge.append("SMTP: Check open relay, user enum. Use smtp-user-enum")
        if "3306" in services_str:
            knowledge.append("MySQL(3306): CRITICAL - Check weak auth immediately")
        if "docker" in services_str.lower():
            knowledge.append("Docker: Check exposed API. Tags: 'docker','cve'")
        
        if not knowledge:
            return "[EXPERT KNOWLEDGE]: Generic audit - use 'exposure','cve','misconfig' tags"
        
        return f"[EXPERT KNOWLEDGE]: {', '.join(knowledge)}"
    
    def _build_concise_prompt(self, host: Host, iteration: int, services_str: str, history_str: str, 
                             findings: str, expert_rag: str, tech_stack_section: str, 
                             anomaly_section: str, hypothesis_section: str, 
                             deep_dive_section: str, deep_dive_recommendations: List[str], 
                             history: List[str] = None) -> str:
        """v18.5: Structured prompt optimized for DeepSeek v3"""
        
        executed_tools = history or []
        history_str_new = "\n".join([f"- {t} \u2713 (YA USADO)" for t in executed_tools if t != "stop"])
        
        actions = self._build_relevant_actions(host, services_str, tech_stack_section, executed_tools)
        
        # v17.5: Build detailed services section with security recommendations
        open_ports = [s for s in host.services if s.state == 'open']
        services_detail = ""
        if open_ports:
            services_detail = "\n[SERVICIOS CONFIRMADOS - PUERTOS ABIERTOS]:\n"
            for s in open_ports[:25]:  # Top 25 services
                service_line = f"  - Puerto {s.port}/{s.protocol}: {s.name}"
                if s.product:
                    service_line += f" ({s.product}"
                    if s.version:
                        service_line += f" {s.version}"
                    service_line += ")"
                
                # v17.5: Add security recommendations per service
                security_note = ""
                if s.port == 21:
                    security_note = " → FTP: test anonymous access, brute force"
                elif s.port in [25, 587, 465]:
                    security_note = " → SMTP: test open relay, user enumeration"
                elif s.port == 3306:
                    security_note = " → MySQL: CRITICAL - test default creds, exposure"
                elif s.port == 53:
                    security_note = " → DNS: test zone transfer, recursion"
                elif s.port in [80, 443]:
                    security_note = " → HTTP/HTTPS: web app security tests"
                elif s.port == 22:
                    security_note = " → SSH: test weak keys, version vulns"
                elif s.port == 3389:
                    security_note = " → RDP: test BlueKeep, authentication"
                elif s.port == 445:
                    security_note = " → SMB: test EternalBlue, anonymous access"
                
                services_detail += service_line + security_note + "\n"
        else:
            services_detail = "\n[SERVICIOS CONFIRMADOS]: Ninguno (requiere rescan)\n"
        
        # v17.5: Build port summary
        port_summary = f"{len(open_ports)} puertos abiertos" if open_ports else "Ningún puerto abierto detectado"
        if open_ports:
            port_list = ", ".join([f"{s.port}/{s.name}" for s in open_ports[:15]])
            if len(open_ports) > 15:
                port_list += f" (+{len(open_ports)-15} más)"
            port_summary = f"{len(open_ports)} abiertos: {port_list}"
        
        prompt = f"""### ROL: Senior Pentester Automatizado (v17.5)
{expert_rag}

{tech_stack_section}

{services_detail}

{current_state}

{system_recommendations}

{anomaly_section}{hypothesis_section}{deep_dive_section}

### ESTADO DEL OBJETIVO:
- Host: {host.hostname or host.ip}
- Resumen de puertos: {port_summary}
- Servicios detectados: {services_str[:400] if services_str else 'Ninguno - requiere rescan'}

### HERRAMIENTAS EJECUTADAS (NO SUGERIR):
{history_str_new if history_str_new else "- Ninguna"}

### REGLAS DE DECISIÓN:
1. NO sugerir herramientas de la lista "YA USADO".
2. Elegir basado en el contexto actual y evidencias.
3. Si no hay opciones válidas o la auditoría está completa, usar "stop".
4. Nuclei: usar tags específicos (ej: wordpress, cve) solo si aplica.

### HERRAMIENTAS DISPONIBLES (elige UNA):
{actions}

### RESPUESTA (JSON):
{{"thought": "razonamiento corto", "decision": {{"tool": "nombre_herramienta", "tags": "opcional", "reason": "por qué"}}, "stop": false}}"""
        return prompt
    
    def _build_relevant_actions(self, host: Host, services_str: str, tech_stack_section: str, history: List[str] = None) -> str:
        """v17.5: Enhanced action builder - validates against ACTUAL detected ports"""
        blocked_set = set(history or [])
        actions = []
        
        # v17.5: Get actual open ports from host.services for validation
        open_ports = [s.port for s in host.services if s.state == 'open']
        open_port_set = set(open_ports)
        
        # Mandatory tools if not used
        if "nuclei" not in blocked_set:
            actions.append("- nuclei: Escáner de vulnerabilidades (especificar tags en 'tags')")
        if "stop" not in blocked_set:
            actions.append("- stop: Terminar la auditoría para este host si no hay más que hacer")
        
        # v17.5: Web context tools - validate against ACTUAL ports
        web_ports = {80, 443, 8080, 8443}
        if open_port_set.intersection(web_ports):
            if "dirsearch" not in blocked_set:
                actions.append("- dirsearch: Enumeración de directorios y archivos ocultos")
            if "feroxbuster" not in blocked_set:
                actions.append("- feroxbuster: Fuzzing web recursivo de alta velocidad")
            if "nikto" not in blocked_set:
                actions.append("- nikto: Escáner de servidor web (vulnerabilidades comunes)")
            if "sqlmap" not in blocked_set:
                actions.append("- sqlmap: Pruebas de inyección SQL (si hay parámetros sospechosos)")
        
        # v17.5: CMS specific - check both tech_stack and web_context
        tech_lower = tech_stack_section.lower()
        services_lower = services_str.lower()
        
        # WordPress detection - check multiple sources
        has_wordpress = ("wordpress" in tech_lower or 
                        "wordpress" in services_lower or
                        (hasattr(host, 'web_context') and host.web_context and 
                         host.web_context.cms_detected and 
                         "wordpress" in host.web_context.cms_detected.lower()))
        
        if has_wordpress and "wpscan" not in blocked_set:
            actions.append("- wpscan: Auditoría completa de WordPress (plugins, temas, usuarios)")
        # Joomla detection
        elif ("joomla" in tech_lower or "joomla" in services_lower) and "joomscan" not in blocked_set:
            actions.append("- joomscan: Auditoría de Joomla")
        # Drupal detection
        elif ("drupal" in tech_lower or "drupal" in services_lower) and "droopescan" not in blocked_set:
            actions.append("- droopescan: Auditoría de Drupal")
        
        # v17.5: FTP - validate against ACTUAL ports
        if 21 in open_port_set and "ftp_scanner" not in blocked_set:
            actions.append("- ftp_scanner: Verificación de FTP (anonymous access, weak auth)")
        
        # v17.5: POP3/IMAP - validate against ACTUAL ports
        mail_ports = {110, 143, 993, 995}
        if open_port_set.intersection(mail_ports) and "mail_scanner" not in blocked_set:
            detected_mail = [p for p in open_ports if p in mail_ports]
            actions.append(f"- mail_scanner: Verificación de servicios de correo (puertos: {', '.join(map(str, detected_mail))})")
        
        # v17.5: Database specific - validate against ACTUAL ports
        db_ports = {3306, 5432, 1433, 27017, 6379}
        detected_db = open_port_set.intersection(db_ports)
        if detected_db:
            if 3306 in detected_db and "mysql-client" not in blocked_set:
                actions.append("- mysql-client: Verificación de exposición de MySQL y login sin pass")
            if 5432 in detected_db and "postgres-scanner" not in blocked_set:
                actions.append("- postgres-scanner: Verificación de PostgreSQL")
            if 1433 in detected_db and "mssql-scanner" not in blocked_set:
                actions.append("- mssql-scanner: Verificación de MSSQL")
            if 27017 in detected_db and "mongodb-scanner" not in blocked_set:
                actions.append("- mongodb-scanner: Verificación de MongoDB")
            if 6379 in detected_db and "redis-scanner" not in blocked_set:
                actions.append("- redis-scanner: Verificación de Redis")
        
        # v17.5: Mail/SMTP - validate against ACTUAL ports
        smtp_ports = {25, 587, 465}
        if open_port_set.intersection(smtp_ports) and "smtp-user-enum" not in blocked_set:
            detected_smtp = [p for p in open_ports if p in smtp_ports]
            actions.append(f"- smtp-user-enum: Enumeración de usuarios SMTP (puertos: {', '.join(map(str, detected_smtp))})")
            
        # v17.5: Infrastructure - validate against ACTUAL ports
        if 22 in open_port_set and "ssh_scanner" not in blocked_set:
            actions.append("- ssh_scanner: Verificación de seguridad y versiones de SSH")
        
        # v17.5: DNS - validate against ACTUAL ports
        if 53 in open_port_set and "dns_scanner" not in blocked_set:
            actions.append("- dns_scanner: Verificación de DNS (zone transfer, recursion, etc.)")
        
        # v17.5: RDP - validate against ACTUAL ports
        if 3389 in open_port_set and "rdp_scanner" not in blocked_set:
            actions.append("- rdp_scanner: Verificación de seguridad RDP")
        
        # v17.5: SMB - validate against ACTUAL ports
        if 445 in open_port_set and "smb_scanner" not in blocked_set:
            actions.append("- smb_scanner: Verificación de seguridad SMB")
        
        return "\n".join(actions)

    def analyze_finding(self, description: str, title: str) -> str:
        """v1.0: Análisis profundo de hallazgo usando LLM - respuesta en español."""
        if not self.enabled: return "Análisis AI no disponible."
        
        prompt = f"""
Eres un analista de seguridad senior. Analiza este hallazgo de seguridad y proporciona una perspectiva ejecutiva profesional y concisa EN ESPAÑOL.

Hallazgo: {title}
Detalles: {description}

Responde SOLO con el análisis (máximo 2 oraciones) en español. Sé específico sobre el impacto y la urgencia.
"""
        res = self._call_llm_with_retry(prompt)
        if res:
            # Limpiar respuesta si viene con markdown o formato extraño
            res = res.strip()
            if res.startswith('"') and res.endswith('"'):
                res = res[1:-1]
            return res
        return "Análisis pendiente."

    def _heuristic_fallback(self, host: Host, history: List[str], tech_stack: Dict[str, Any] = None, findings: List[Any] = None) -> Dict[str, Any]:
        """v17.4: Intelligent fallback using audit profiles."""
        from ..intelligence.audit_profiles import AuditProfileManager
        
        tools = []
        tags = ""
        
        # v17.4: Use audit profiles for intelligent fallback
        profile_manager = AuditProfileManager()
        next_tool = profile_manager.get_intelligent_fallback(
            host, tech_stack or {}, history, findings or []
        )
        
        if next_tool:
            tools.append(next_tool)
            # Extract tags if it's a nuclei tool
            if next_tool.startswith("nuclei"):
                if "tags=" in next_tool:
                    tags = next_tool.split("tags=")[1]
                else:
                    tags = "exposure,cve,misconfig"
        else:
            # Fallback to basic heuristic if profile exhausted
            ports = [s.port for s in host.services if s.state == 'open']
            if 443 in ports and "sslscan" not in history: 
                tools.append("sslscan")
            elif "nuclei" not in history: 
                tools.append("nuclei")
                tags = "exposure,cve,misconfig"
            elif (80 in ports or 443 in ports) and "feroxbuster" not in history: 
                tools.append("feroxbuster")

        return {
            "thought": "LLM unavailable. Using intelligent audit profile fallback.",
            "analysis": { "host_class": host.classification.value, "evidence_summary": "Profile-based fallback" },
            "hypothesis_refinement": { "current_hypothesis": "Technology-specific audit", "confidence": 0.7, "next_verification": "Profile-guided scan" },
            "decision": { "tool": tools[0] if tools else "stop", "tools": tools, "tags": tags, "justification": "Audit profile recommendation" },
            "stop": len(tools) == 0,
            "stop_reason": "All profile tools executed or no suitable tools available."
        }


