import logging
from logging.handlers import RotatingFileHandler

class Logger:
    def __init__(self, log_path):
        self.logger = logging.getLogger("LabminApp")
        self.logger.setLevel(logging.DEBUG)

        handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def info(self, msg):
        self.logger.info(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)