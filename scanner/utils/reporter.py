import json
import logging
from colorama import Fore, Style

logger = logging.getLogger("VulnScanner")

class Reporter:
    def __init__(self, results):
        self.results = results

    def print_summary(self):
        print(f"\n{Style.BRIGHT}--- Scan Summary for {self.results['target']} ---{Style.RESET_ALL}\n")
        
        # Open Ports
        if self.results['open_ports']:
            print(f"{Fore.GREEN}[+] Open Ports:{Style.RESET_ALL}")
            for port in self.results['open_ports']:
                print(f"    - Port {port} is open")
        else:
            print(f"{Fore.YELLOW}[-] No open ports found.{Style.RESET_ALL}")
            
        print()
        
        # Security Headers
        headers = self.results.get('security_headers', {})
        if headers:
            print(f"{Fore.GREEN}[+] Security Headers:{Style.RESET_ALL}")
            if headers.get('missing'):
                print(f"    {Fore.RED}Missing Headers:{Style.RESET_ALL}")
                for h in headers['missing']:
                    print(f"      - {h}")
            if headers.get('present'):
                print(f"    {Fore.GREEN}Present Headers:{Style.RESET_ALL}")
                for h in headers['present']:
                    print(f"      - {h}")
        
        print()
        
        # Vulnerabilities
        vulns = self.results.get('vulnerabilities', [])
        if vulns:
            print(f"{Fore.RED}{Style.BRIGHT}[!] Vulnerabilities Found ({len(vulns)}):{Style.RESET_ALL}")
            for v in vulns:
                print(f"    - Type: {Fore.RED}{v['type']}{Style.RESET_ALL}")
                print(f"      URL: {v['url']}")
                if 'param' in v:
                    print(f"      Parameter: {v['param']}")
                if 'payload' in v:
                    print(f"      Payload: {v['payload']}")
                print()
        else:
            if self.results.get('crawled_urls'):
                print(f"{Fore.GREEN}[+] No obvious XSS/SQLi vulnerabilities found in {len(self.results['crawled_urls'])} URLs.{Style.RESET_ALL}")
        
        print(f"\n{Style.BRIGHT}---------------------------------------{Style.RESET_ALL}\n")

    def save_json(self, file_path):
        with open(file_path, 'w') as f:
            json.dump(self.results, f, indent=4)
