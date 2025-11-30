"""
Unified Email Analyzer - Coordinates multiple agents for comprehensive phishing detection.
"""
import json
from typing import Optional
from text_agent_v2 import TextAgent
from url_agent_v2 import URLAgent


class UnifiedEmailAnalyzer:
    """Coordinates text and URL agents for comprehensive phishing detection."""
    
    def __init__(self, model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        self.text_agent = TextAgent(model, ollama_url)
        self.url_agent = URLAgent(model, ollama_url)
        self.model = model
        self.ollama_url = ollama_url
    
    def analyze_email(self, subject: str, body: str, urls: Optional[list] = None) -> dict:
        """
        Analyze an email using all available agents and merge results.
        
        Args:
            subject: Email subject line
            body: Email body text
            urls: Optional list of URLs found in the email
        
        Returns:
            Unified analysis with verdicts from all agents
        """
        if urls is None:
            urls = []
        
        # Run both agents
        text_result = self.text_agent.analyze(subject=subject, body=body)
        url_result = self.url_agent.analyze(urls=urls) if urls else None
        
        # Merge results
        merged = self._merge_results(text_result, url_result)
        return merged
    
    def _merge_results(self, text_result: dict, url_result: Optional[dict]) -> dict:
        """Merge text and URL agent results into unified verdict."""
        
        # Map verdict strings to numeric values for scoring
        verdict_scores = {"phishing": 1.0, "unsure": 0.5, "legitimate": 0.0}
        
        text_score = verdict_scores.get(text_result.get("verdict", "unsure"), 0.5)
        text_confidence = text_result.get("confidence", 0.5)
        
        # If URL analysis is available, factor it in
        if url_result:
            url_score = verdict_scores.get(url_result.get("verdict", "unsure"), 0.5)
            url_confidence = url_result.get("confidence", 0.5)
            
            # Weighted average: text gets 60%, URL gets 40%
            combined_score = (text_score * 0.6 * text_confidence) + (url_score * 0.4 * url_confidence)
            combined_confidence = (text_confidence * 0.6) + (url_confidence * 0.4)
            urls_analyzed = True
        else:
            combined_score = text_score * text_confidence
            combined_confidence = text_confidence
            urls_analyzed = False
        
        # Determine final verdict
        if combined_score >= 0.7:
            final_verdict = "phishing"
        elif combined_score <= 0.3:
            final_verdict = "legitimate"
        else:
            final_verdict = "unsure"
        
        # Compile all indicators
        all_phishing_indicators = text_result.get("phishing_indicators", [])
        all_legitimacy_indicators = text_result.get("legitimacy_indicators", [])
        
        if url_result:
            url_indicators = [d.get("indicators", []) for d in url_result.get("url_details", [])]
            for indicators_list in url_indicators:
                all_phishing_indicators.extend(indicators_list)
        
        # Build unified result
        unified = {
            "task": "email_phishing_detection",
            "verdict": final_verdict,
            "confidence": round(combined_confidence, 2),
            "phishing_indicators": list(set(all_phishing_indicators)),
            "legitimacy_indicators": all_legitimacy_indicators,
            "agents_used": {
                "text": True,
                "url": urls_analyzed
            },
            "text_agent_result": text_result,
            "url_agent_result": url_result,
            "overall_rationale": self._build_rationale(final_verdict, text_result, url_result),
            "safety_notes": text_result.get("safety_notes", "")
        }
        
        return unified
    
    @staticmethod
    def _build_rationale(verdict: str, text_result: dict, url_result: Optional[dict]) -> str:
        """Build a summary rationale from agent results."""
        text_rationale = text_result.get("overall_rationale", "")
        
        if url_result:
            url_rationale = url_result.get("overall_rationale", "")
            return f"Text analysis: {text_rationale}\n\nURL analysis: {url_rationale}"
        else:
            return f"Based on text analysis: {text_rationale}"


def analyze_email(subject: str, body: str, urls: Optional[list] = None) -> dict:
    """Convenience function to analyze an email."""
    analyzer = UnifiedEmailAnalyzer()
    return analyzer.analyze_email(subject=subject, body=body, urls=urls)


if __name__ == "__main__":
    # Quick manual test
    test_subject = "Important: Verify your account immediately"
    test_body = (
        "Dear user,\n\nWe detected unusual activity in your account. "
        "If you do not verify your password within 24 hours, your account will be closed. "
        "Please click the link below to verify your account.\n\nBest regards,\nSecurity Team"
    )
    test_urls = ["http://verify-account-security.com/login"]

    analysis = analyze_email(test_subject, test_body, test_urls)
    print(json.dumps(analysis, indent=2))
