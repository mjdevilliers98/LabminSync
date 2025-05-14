from abc import ABC, abstractmethod

class BaseDevice(ABC):
    def __init__(self, name, config_path, logger, gui):
        self.name = name
        self.config_path = config_path
        self.logger = logger
        self.gui = gui
        self.running = False
        self.log_view = None

    @abstractmethod
    def run(self):
        pass

    def stop(self):
        self.running = False
        self.append_log("Device stopped.")

    def append_log(self, message):
        self.logger.info(f"[{self.name}] {message}")
        if self.gui:
            self.gui.append_log(self.name, message)
