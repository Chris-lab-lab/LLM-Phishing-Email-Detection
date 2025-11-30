"""
URL Agent v2 - Analyzes URLs in emails for phishing indicators.
"""
import json
from typing import Optional, List
from urllib.parse import urlparse
from base_agent import BaseAgent


URL_AGENT_SYSTEM_PROMPT = '''
You are the URL AGENT in a multi-agent phishing email detection system.

GOAL
- Analyze URLs found in an email for phishing indicators.
- Assess the risk level of each URL independently.
- Produce a STRICT JSON object as output, with no extra text.

WHAT YOU ANALYZE
- URL structure (HTTPS vs HTTP, domain legitimacy, suspicious patterns)
- Domain reputation indicators (typosquatting, lookalike domains, newly registered)
- URL obfuscation techniques (shorteners, encoded parameters, redirects)
- Known phishing patterns (verify, confirm, update, login, secure, etc.)

WHAT YOU DO NOT ANALYZE
- The actual content of landing pages (no browser rendering)
- The email text or subject (separate Text Agent handles this)
- File metadata or network logs

URL-BASED PHISHING INDICATORS
Look for:
- http_not_https: Unencrypted connection
- domain_mismatch: URL doesn't match sender domain
- suspicious_domain: Typosquatting, unusual TLD, newly registered
- url_shortener: Bit.ly, TinyURL, etc. (hides real destination)
- credential_harvesting_keywords: "verify", "confirm", "login", "update", "secure"
- suspicious_parameters: Encoded payloads, excessive parameters
- ip_address_instead_of_domain: Direct IP connections

OUTPUT FORMAT (STRICT JSON)
Return a SINGLE valid JSON object with this schema:

{
    "agent": "url",
    "version": "1.0",
    "view": "url_only",
    "task": "email_phishing_detection",
    "urls_analyzed": 2,
    "verdict": "phishing | legitimate | unsure",
    "confidence": 0.85,
    "risk_summary": "Moderate risk - 1 suspicious URL found",
    "url_details": [
        {
            "url": "https://example.com/verify",
            "domain": "example.com",
            "is_https": true,
            "risk_level": "high",
            "indicators": ["credential_harvesting_keywords"],
            "explanation": "Domain uses 'verify' keyword commonly seen in phishing"
        }
    ],
    "overall_rationale": "Based on URL analysis alone, verdict is...",
    "safety_notes": "Optional advice for the end user"
}

JSON RULES
- Use double quotes for all keys and string values.
- No comments, no trailing commas.
- If no URLs provided, set "urls_analyzed" to 0 and "verdict" to "unsure".
'''


class URLAgent(BaseAgent):
    """Analyzes URLs in emails for phishing indicators."""
    
    def __init__(self, model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        super().__init__(model, ollama_url)
        self.agent_name = "url"
    
    def get_system_prompt(self) -> str:
        return URL_AGENT_SYSTEM_PROMPT
    
    def prepare_input(self, urls: Optional[List[str]] = None) -> str:
        if not urls:
            urls = []
        urls_text = "\n".join(urls) if urls else "(no URLs provided)"
        return f"URLs to analyze:\n{urls_text}"
    
    def analyze(self, urls: Optional[List[str]]) -> dict:
        """Analyze URLs for phishing indicators."""
        return super().analyze(urls=urls)


def run_url_agent(urls: Optional[List[str]]) -> dict:
    """Legacy interface - call URL agent."""
    agent = URLAgent()
    return agent.analyze(urls=urls)


if __name__ == "__main__":
    # Quick manual test
    test_urls = [
        "http://verify-account.phishing.com",
        "https://github.com/Chris-lab-lab",
        "http://bit.ly/malicious",
    ]

    analysis = run_url_agent(test_urls)
    print(json.dumps(analysis, indent=2))
