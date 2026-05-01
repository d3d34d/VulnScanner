import logging
from urllib.parse import urlparse
from scanner.modules.port_scanner import PortScanner
from scanner.modules.crawler import WebCrawler
from scanner.modules.header_scanner import HeaderScanner
from scanner.modules.web_scanner import WebVulnScanner
from scanner.utils.reporter import Reporter

logger = logging.getLogger("VulnScanner")

class VulnScanner:
    def __init__(self, target, ports, crawl_depth, output_file):
        self.target = target
        self.ports = ports
        self.crawl_depth = crawl_depth
        self.output_file = output_file
        
        self.is_url = target.startswith("http://") or target.startswith("https://")
        if self.is_url:
            parsed = urlparse(target)
            self.host = parsed.netloc.split(':')[0]
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            self.host = target
            self.base_url = f"http://{target}"

        self.results = {
            "target": self.target,
            "host": self.host,
            "open_ports": [],
            "security_headers": {},
            "crawled_urls": [],
            "vulnerabilities": []
        }

    def run(self):
        logger.info(f"Starting vulnerability scan on {self.target}")
        
        # 1. Port Scanning
        logger.info("=== Starting Port Scan ===")
        port_scanner = PortScanner(self.host, self.ports)
        open_ports = port_scanner.scan()
        self.results["open_ports"] = open_ports
        
        # If it's a web target, run web modules
        if self.is_url or 80 in open_ports or 443 in open_ports:
            logger.info("=== Starting Security Headers Check ===")
            header_scanner = HeaderScanner(self.base_url)
            headers_result = header_scanner.scan()
            self.results["security_headers"] = headers_result
            
            logger.info("=== Starting Web Crawler ===")
            crawler = WebCrawler(self.base_url, self.crawl_depth)
            urls, forms = crawler.crawl()
            self.results["crawled_urls"] = list(urls)
            
            logger.info(f"Crawled {len(urls)} URLs and found {len(forms)} forms.")
            
            logger.info("=== Starting Web Vulnerability Scan ===")
            web_scanner = WebVulnScanner(self.base_url, urls, forms)
            vulns = web_scanner.scan()
            self.results["vulnerabilities"] = vulns
            
        # Reporting
        logger.info("=== Scan Complete ===")
        reporter = Reporter(self.results)
        reporter.print_summary()
        
        if self.output_file:
            reporter.save_json(self.output_file)
            logger.info(f"Report saved to {self.output_file}")
