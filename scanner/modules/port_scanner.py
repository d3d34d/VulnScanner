import socket
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("VulnScanner")

class PortScanner:
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                logger.info(f"Port {port} is open")
            sock.close()
        except socket.error:
            pass

    def scan(self):
        logger.info(f"Scanning {len(self.ports)} ports on {self.target}...")
        
        # Use multithreading to speed up port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.scan_port, self.ports)
            
        return sorted(self.open_ports)
