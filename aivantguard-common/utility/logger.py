# aivantguard-common/utility/logger.py
import logging
import os
from datetime import datetime
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_get_tz = ZoneInfo
# --- Logging Configuration ---
# Read configuration from environment variables for flexibility
# Use LOG_LEVEL which is more standard than DEBUG=1
LOG_LEVEL_ENV_VAR = os.getenv("LOG_LEVEL", "INFO").upper()
# Define the desired log format string
# %(module)s provides the source module name, replacing inspect/getcwd logic
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(module)s] - %(message)s"
# Define the desired timestamp format, including a placeholder for milliseconds
LOG_DATE_FORMAT = "%Y.%m.%d %H:%M:%S.%f"
# Define the timezone, configurable via environment variable
LOG_TIMEZONE_NAME = os.getenv("LOG_TIMEZONE", "Europe/Madrid")

# --- Timezone Initialization ---
try:
    # Attempt to load the specified timezone
    _tz = _get_tz(LOG_TIMEZONE_NAME)
except ZoneInfoNotFoundError:
    # Fallback to UTC if the specified timezone is not found
    print(
        f"Warning: Timezone '{LOG_TIMEZONE_NAME}' not found using "
        f"{'zoneinfo' if 'zoneinfo' in sys.modules else 'pytz'}. "
        f"Falling back to UTC.",
        file=sys.stderr
    )
    # Get UTC using the available library
    _tz = ZoneInfo("UTC")


# --- Custom Timezone Formatter ---
class TzFormatter(logging.Formatter):
    """
    A logging formatter that uses a specific timezone for timestamps
    and correctly formats milliseconds using record.msecs.
    """

    def __init__(self, fmt=None, datefmt=None, tz=None, style='%', validate=True):
        # Pass 'validate=True' for Python 3.8+ compatibility if using style='{'
        if sys.version_info >= (3, 8):
            super().__init__(fmt=fmt, datefmt=datefmt, style=style, validate=validate)
        else:
            # 'validate' keyword not available before Python 3.8
            super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.tz = tz

    def formatTime(self, record, datefmt=None):
        """
        Overrides formatTime to apply the specified timezone and handle
        millisecond formatting based on the date format string.
        """
        # Convert record creation time to a timezone-aware datetime object
        dt = datetime.fromtimestamp(record.created, self.tz)

        if datefmt:
            # If the date format includes '%f', format the base time
            # and manually append the milliseconds for precise control.
            if '%f' in datefmt:
                base_fmt = datefmt.replace('%f', '')
                s = dt.strftime(base_fmt) + f".{int(record.msecs):03d}"
            else:
                # Format using the provided datefmt string directly if no %f
                s = dt.strftime(datefmt)
        else:
            # Provide a default ISO 8601 format if no datefmt is specified
            s = dt.isoformat(sep=" ", timespec="milliseconds")
        return s


# --- Logger Setup Function ---
def setup_logger(name="app_logger", level=None):
    """
    Configures and returns a logger instance using the standard logging module.

    Args:
        name (str): The name for the logger (e.g., 'app_logger', __name__).
        level (int | str, optional): The logging threshold level. If None,
            it reads from the LOG_LEVEL environment variable or defaults
            to INFO. Accepts standard logging level integers or names (str).

    Returns:
        logging.Logger: The configured logger instance.
    """
    # Determine the logging level
    if level is None:
        # Default to environment variable or INFO
        log_level = getattr(logging, LOG_LEVEL_ENV_VAR, logging.INFO)
    elif isinstance(level, str):
        # Convert string level name to logging constant
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        # Assume level is an integer constant (e.g., logging.DEBUG)
        log_level = int(level)

    # Get the logger instance
    _logger = logging.getLogger(name)
    _logger.setLevel(log_level)

    # Avoid adding duplicate handlers if setup_logger is called multiple times
    if _logger.hasHandlers():
        _logger.handlers.clear()

    # Create a handler to output logs to stdout (matching original behavior)
    # Use sys.stderr for standard error logging if preferred
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create the custom formatter with timezone and specific date format
    formatter = TzFormatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, tz=_tz)
    console_handler.setFormatter(formatter)

    # Add the configured handler to the logger
    _logger.addHandler(console_handler)

    # Optional: Prevent log messages from propagating to the root logger
    # if using hierarchical loggers and specific handling is desired.
    # logger.propagate = False

    return _logger


# --- Global Logger Instance ---
# Set up a default logger instance when the module is imported.
# In larger applications, this setup might be called explicitly
# in the main application entry point.
logger = setup_logger()

# --- Example Usage (Optional - can be removed) ---
# To demonstrate how to use the logger in other modules:
#
# import logging
# logger = logging.getLogger("app_logger") # Get the already configured logger
#
# logger.debug("Detailed information for developers.") # Shown if LOG_LEVEL=DEBUG
# logger.info("Standard operational message.")
# logger.warning("Potential issue detected.")
# logger.error("An error occurred that prevented normal operation.")
# logger.critical("A critical error occurred, application may crash.")
#
# try:
#     1 / 0
# except ZeroDivisionError:
#     # logger.exception logs an ERROR level message including stack trace
#     logger.exception("An unexpected error happened during division.")
