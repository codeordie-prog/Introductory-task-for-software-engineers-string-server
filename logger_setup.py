import os 
import logging
from typing import Any, Union, Optional

class Logger:
    """
    This class implements a singleton logger that writes logs to a file.
    It supports different logging levels and automatically creates the log directory if it doesn't exist.
    
    Attributes:
        logger (logging.Logger): The underlying logger instance that handles the actual logging.
    
    Example:
        >>> logger = Logger("logs/app.log", "DEBUG")
        >>> logger.info("Application started")
        >>> logger.error("An error occurred")
    """
    def __init__(self, logging_file: str = "logs/server_logs.log", logging_level: str = "DEBUG") -> None:
        self.logger: logging.Logger = self._logger_setup(logging_file, logging_level)

    def _logger_setup(self, logging_file: str, logging_level: str) -> logging.Logger:
        """Sets up the logger.
        Args:
            logging_file(str) : Path to server_log file.
            logging_level(str) : log level, defaults to "DEBUG".

        Returns:
            logger (logging.Logger): Configured logger with file and stream handlers.
        """
        # Make the logging file directory if it does not exist.
        os.makedirs(os.path.dirname(logging_file), exist_ok=True)

        logger: logging.Logger = logging.getLogger("ServerLogs")

        # Set the logging level - defaults to 'DEBUG' level.
        logger.setLevel(getattr(logging, logging_level.upper(), logging.DEBUG))

        # Prevent duplicate logs.
        if logger.hasHandlers():
            return logger
        
        # Set formatter.
        formatter: logging.Formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(message)s]'
        )

        # Set file handler.
        file_handler: logging.FileHandler = logging.FileHandler(logging_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level="DEBUG")

        # Set stream handler.
        stream_handler: logging.StreamHandler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel("DEBUG")

        # Add handlers to logger.
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        # Return logger.
        return logger
    
    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the internal logger."""
        return getattr(self.logger, name)
   