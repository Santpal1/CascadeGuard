"""
Centralized logging configuration for CascadeGuard.
All modules should use this instead of print() statements.
"""

import logging
import logging.handlers
import os
from config import CONFIG


def setup_logging(log_file: str = "cascadeguard.log"):
    """
    Initializes the logging system for all CascadeGuard modules.
    
    Args:
        log_file: Path to the log file (optional)
    
    Usage in any module:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Message")
    """
    # Create output directory if needed
    os.makedirs("logs", exist_ok=True)
    os.makedirs(CONFIG.output_dir, exist_ok=True)
    
    # Get root logger
    root_logger = logging.getLogger()
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set root log level
    log_level = getattr(logging, CONFIG.log_level.upper(), logging.INFO)
    root_logger.setLevel(log_level)
    
    # Console handler (INFO and above)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '[%(name)s] %(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (DEBUG and above)
    file_path = os.path.join("logs", log_file)
    file_handler = logging.handlers.RotatingFileHandler(
        file_path,
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Gets a logger for a specific module.
    
    Usage:
        from logging_config import get_logger
        logger = get_logger(__name__)
        logger.info("Message")
    """
    return logging.getLogger(name)
