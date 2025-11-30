"""
Base Agent - Shared functionality for all email analysis agents.
"""
import json
import requests
from abc import ABC, abstractmethod
from typing import Optional


class BaseAgent(ABC):
    """Abstract base class for email analysis agents."""
    
    def __init__(self, model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        self.model = model
        self.ollama_url = ollama_url
        self.agent_name = ""
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent."""
        pass
    
    @abstractmethod
    def prepare_input(self, **kwargs) -> str:
        """Prepare the user message from input parameters."""
        pass
    
    def call_llm(self, system_prompt: str, user_message: str) -> dict:
        """Call Ollama LLM and parse JSON response."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "stream": False
        }
        
        resp = requests.post(f"{self.ollama_url}/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        
        raw_content = data["message"]["content"]
        return self._extract_json(raw_content)
    
    @staticmethod
    def _extract_json(raw: str) -> dict:
        """Extract JSON object from model output."""
        start = raw.find('{')
        end = raw.rfind('}')
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object found in model output")
        
        json_str = raw[start:end + 1]
        return json.loads(json_str)
    
    def analyze(self, **kwargs) -> dict:
        """Run the analysis. Implement specific logic in subclasses."""
        system_prompt = self.get_system_prompt()
        user_message = self.prepare_input(**kwargs)
        result = self.call_llm(system_prompt, user_message)
        return result
