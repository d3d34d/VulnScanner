import requests
import logging

logger = logging.getLogger("VulnScanner")

class HeaderScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.security_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "X-XSS-Protection"
        ]

    def scan(self):
        result = {
            "present": [],
            "missing": []
        }
        
        try:
            response = requests.get(self.target_url, timeout=5)
            headers = response.headers
            
            for header in self.security_headers:
                if header in headers:
                    result["present"].append(header)
                else:
                    result["missing"].append(header)
                    
            if result["missing"]:
                logger.warning(f"Missing security headers: {', '.join(result['missing'])}")
            else:
                logger.info("All basic security headers are present.")
                
        except requests.RequestException as e:
            logger.error(f"Failed to check headers for {self.target_url}: {e}")
            
        return result
