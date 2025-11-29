"""
Simple URL Agent Demonstration
This module demonstrates basic URL analysis and phishing detection patterns.
"""

def is_suspicious_url(url: str) -> bool:
    """
    Check if a URL contains common phishing indicators.
    
    Args:
        url: The URL string to analyze
    
    Returns:
        bool: True if URL appears suspicious, False otherwise
    """
    suspicious_patterns = [
        "http://",  # Not HTTPS
        "bit.ly",   # URL shortener
        "tinyurl",  # URL shortener
        "phishing", # Common keyword
        "verify",   # Common phishing action
        "confirm",  # Common phishing action
    ]
    
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in suspicious_patterns)


def extract_domain(url: str) -> str:
    """
    Extract the domain from a URL.
    
    Args:
        url: The URL string
    
    Returns:
        str: The domain name
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except Exception as e:
        return f"Error extracting domain: {str(e)}"


def main():
    """Demonstration of URL agent functionality."""
    print("=== URL Agent Demonstration ===\n")
    
    test_urls = [
        "https://www.google.com",
        "http://verify-account.phishing.com",
        "https://github.com/Chris-lab-lab",
        "http://bit.ly/malicious",
    ]
    
    for url in test_urls:
        domain = extract_domain(url)
        is_suspicious = is_suspicious_url(url)
        status = "⚠️  SUSPICIOUS" if is_suspicious else "✓ SAFE"
        
        print(f"URL: {url}")
        print(f"Domain: {domain}")
        print(f"Status: {status}\n")


if __name__ == "__main__":
    main()
