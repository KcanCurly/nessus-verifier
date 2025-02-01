import logging
import sys

# Standard logging levels
DEFAULT_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Custom logging levels
V0 = 5
V1 = 15
V2 = 25
V3 = 35
V4 = 45
V5 = 55

CUSTOM_LEVELS = {
    0: V0,
    1: V1,
    2: V2,
    3: V3,
    4: V4,
    5: V5,
}

# Add custom levels to logging
logging.addLevelName(V0, "V0")
logging.addLevelName(V1, "V1")
logging.addLevelName(V2, "V2")
logging.addLevelName(V3, "V3")
logging.addLevelName(V4, "V4")
logging.addLevelName(V5, "V5")


# Extend logging.Logger to include custom levels
class CustomLogger(logging.Logger):
    def v0(self, message, *args, **kwargs):
        if self.isEnabledFor(V0):
            self._log(V0, message, args, **kwargs)

    def v1(self, message, *args, **kwargs):
        if self.isEnabledFor(V1):
            self._log(V1, message, args, **kwargs)
            
    def v2(self, message, *args, **kwargs):
        if self.isEnabledFor(V2):
            self._log(V2, message, args, **kwargs)
            
    def v3(self, message, *args, **kwargs):
        if self.isEnabledFor(V3):
            self._log(V3, message, args, **kwargs)
            
    def v4(self, message, *args, **kwargs):
        if self.isEnabledFor(V4):
            self._log(V4, message, args, **kwargs)
            
    def v5(self, message, *args, **kwargs):
        if self.isEnabledFor(V5):
            self._log(V5, message, args, **kwargs)


class LevelBasedFormatter(logging.Formatter):
    """Custom formatter that changes log format based on the logging level."""
    
    FORMATS = {
        V0:    "[V0] %(message)s",
        V1:    "[V1] %(message)s",
        V2:      "[V2] %(message)s",
        V3:   "[V3] %(message)s",
        V4:     "[V4] %(message)s",
        V5:     "[V5] %(message)s",
        logging.DEBUG:    "[DEBUG]  %(message)s",
        logging.INFO:     "[INFO]  %(message)s",
        logging.WARNING:  "[WARNING]  %(message)s",
        logging.ERROR:    "[ERROR]  %(message)s",
        logging.CRITICAL: "[CRITICAL]  %(message)s",
    }

    def format(self, record):
        """Select format based on log level."""
        log_fmt = self.FORMATS.get(record.levelno, "[UNKNOWN] | %(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging(verbosity=0, standard_level=None):
    """
    Configure logging with both custom and standard logging levels.
    
    :param verbosity: int, Number of `-v` flags for custom logging (0-5)
    :param standard_level: str, Standard logging level ("INFO", "WARNING", etc.)
    """
    if standard_level and standard_level.upper() in DEFAULT_LEVELS:
        log_level = DEFAULT_LEVELS[standard_level.upper()]
    else:
        print(verbosity)
        log_level = CUSTOM_LEVELS.get(verbosity, logging.DEBUG)  # Default to DEBUG
        print(log_level)

    # Set custom logger class
    logging.setLoggerClass(CustomLogger)
    logger = logging.getLogger("nv_logger")
    logger.setLevel(log_level)
    handler = logging.StreamHandler()
    handler.setFormatter(LevelBasedFormatter())
    logger.addHandler(handler)
    return logger  # Return the configured logger instance
