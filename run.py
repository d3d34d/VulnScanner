import argparse
from scanner.main import VulnScanner
from scanner.utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description="Automated Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP address (e.g., http://example.com or 192.168.1.1)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan", default="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080")
    parser.add_argument("-d", "--depth", type=int, help="Crawling depth", default=2)
    parser.add_argument("-o", "--output", help="Output JSON report file path", default=None)
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print("[-] Invalid port list. Please provide comma-separated integers.")
        return

    setup_logger()
    
    scanner = VulnScanner(
        target=args.target,
        ports=ports,
        crawl_depth=args.depth,
        output_file=args.output
    )
    
    scanner.run()

if __name__ == "__main__":
    main()
