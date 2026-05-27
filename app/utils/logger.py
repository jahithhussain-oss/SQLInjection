import logging
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:   Fore.CYAN,
        logging.INFO:    Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR:   Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}"


def get_logger(name: str = "sql-scanner") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(
            ColorFormatter("[%(levelname)s] %(asctime)s - %(message)s", datefmt="%H:%M:%S")
        )
        logger.addHandler(handler)
    return logger
