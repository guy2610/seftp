import  logging
import sys

LEVELS={"CRITICAL":logging.CRITICAL,
        "ERROR":logging.ERROR,
        "WARNING":logging.WARNING,
        "INFO":logging.INFO,
        "DEBUG":logging.DEBUG,
        }
class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "connection_id"):
            record.connection_id = "-"
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return super().format(record)

class SessionLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.setdefault("connection_id", getattr(self, "connection_id", "-"))
        extra.setdefault("request_id", getattr(self, "request_id", "-"))
        kwargs["extra"] = extra
        return msg, kwargs

def setup_logging(level_str: str) -> logging.Logger:
    level = LEVELS.get(str(level_str).upper(), logging.INFO)

    logger = logging.getLogger("seftp.server")
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setLevel(level)
        fmt = SafeFormatter(
            "%(asctime)s %(levelname)s %(name)s conn=%(connection_id)s req=%(request_id)s %(message)s"
        )
        h.setFormatter(fmt)
        logger.addHandler(h)
    return logger

def make_session_logger(base_logger: logging.Logger, connection_id: str) -> SessionLoggerAdapter:
    adapter = SessionLoggerAdapter(base_logger, {})
    adapter.connection_id = connection_id
    adapter.request_id = "-"
    return adapter