import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging

logger = logging.getLogger("VulnScanner")

class WebVulnScanner:
    def __init__(self, base_url, urls, forms):
        self.base_url = base_url
        self.urls = urls
        self.forms = forms
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Basic payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]
        
        self.sqli_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1"
        ]
        
        self.sqli_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated"
        ]

    def test_xss_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
            
        for param in params:
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        logger.warning(f"Potential XSS found at {url} in parameter '{param}'")
                        self.vulnerabilities.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "url": url,
                            "param": param,
                            "payload": payload
                        })
                        break # Move to next param if vuln found
                except requests.RequestException:
                    pass

    def test_sqli_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
            
        for param in params:
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text.lower()
                    
                    for error in self.sqli_errors:
                        if error in response_text:
                            logger.warning(f"Potential SQLi found at {url} in parameter '{param}'")
                            self.vulnerabilities.append({
                                "type": "SQL Injection",
                                "url": url,
                                "param": param,
                                "payload": payload
                            })
                            break
                except requests.RequestException:
                    pass

    def test_xss_form(self, form):
        url = form["url"]
        method = form["method"]
        inputs = form["inputs"]
        
        for payload in self.xss_payloads:
            data = {}
            for inp in inputs:
                if inp["type"] == "text":
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = "test"
            
            try:
                if method == "post":
                    response = self.session.post(url, data=data, timeout=5)
                else:
                    response = self.session.get(url, params=data, timeout=5)
                    
                if payload in response.text:
                    logger.warning(f"Potential XSS found in form at {url}")
                    self.vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS) via Form",
                        "url": url,
                        "payload": payload
                    })
                    break
            except requests.RequestException:
                pass

    def scan(self):
        logger.info("Scanning URLs for XSS and SQLi...")
        for url in self.urls:
            self.test_xss_url(url)
            self.test_sqli_url(url)
            
        logger.info("Scanning Forms for XSS...")
        for form in self.forms:
            self.test_xss_form(form)
            # You can also add sqli form scanning similarly
            
        return self.vulnerabilities
