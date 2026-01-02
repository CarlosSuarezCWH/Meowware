import json
import os
import requests
import time
from typing import List, Dict, Any, Optional
from ...core.debug import debug_print, debug_ai_prompt, debug_ai_response
from ...core.models import Host

class BaseAgent:
    def __init__(self, agent_name: str, model: str = None):
        self.agent_name = agent_name
        self.api_key = os.environ.get('DEEPSEEK_API_KEY', '')
        self.api_provider = os.environ.get('LLM_PROVIDER', 'deepseek').lower()
        self.api_url = os.environ.get('LLM_URL', "")
        
        if self.api_provider == 'deepseek':
            self.model = model or "deepseek-chat"
            if not self.api_url:
                self.api_url = "https://api.deepseek.com/v1/chat/completions"
        else:
            self.model = model or "llama3" # Default to llama3 for Ollama in v18.0
            if not self.api_url:
                self.api_url = "http://localhost:11434/api/generate"
        
        self.enabled = True
        if self.api_provider == 'deepseek' and not self.api_key:
            self.enabled = False
            
    def _call_llm(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        if not self.enabled:
            return None
            
        system_prompt = system_prompt or f"You are the {self.agent_name} agent of Meowware, an advanced offensive security platform. Respond with valid JSON only."
        
        try:
            if self.api_provider == 'deepseek':
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2, # Lower temperature for better consistency
                    "max_tokens": 2000
                }
                response = requests.post(self.api_url, json=payload, headers=headers, timeout=120)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('choices', [{}])[0].get('message', {}).get('content', '{}')
            else:
                # Ollama
                payload = {
                    "model": self.model,
                    "prompt": f"System: {system_prompt}\nUser: {prompt}",
                    "stream": False,
                    "format": "json"
                }
                response = requests.post(self.api_url, json=payload, timeout=900)
                if response.status_code == 200:
                    return response.json().get('response', '{}')
        except Exception as e:
            debug_print(f"  [Agent {self.agent_name}] Error calling LLM: {str(e)}")
            
        return None

    def _clean_json(self, text: str) -> str:
        if not text: return "{}"
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def run(self, host: Host, context: Dict[str, Any]) -> Dict[str, Any]:
        """To be implemented by subclasses"""
        raise NotImplementedError
