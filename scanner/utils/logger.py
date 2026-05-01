import logging
import colorama
from colorama import Fore, Style

class ColorFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Style.DIM + "%(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.CYAN + "[*] " + Style.RESET_ALL + "%(message)s",
        logging.WARNING: Fore.YELLOW + "[!] " + Style.RESET_ALL + "%(message)s",
        logging.ERROR: Fore.RED + "[-] " + Style.RESET_ALL + "%(message)s",
        logging.CRITICAL: Fore.RED + Style.BRIGHT + "[!!!] %(message)s" + Style.RESET_ALL
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logger():
    colorama.init()
    logger = logging.getLogger("VulnScanner")
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(ColorFormatter())
    
    if not logger.handlers:
        logger.addHandler(ch)
    
    return logger
