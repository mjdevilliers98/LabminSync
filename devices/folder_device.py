import time
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_device import BaseDevice

class FolderEventHandler(FileSystemEventHandler):
    def __init__(self, device):
        self.device = device

    def on_created(self, event):
        if event.is_directory:
            return
        self.device.append_log(f"New file detected: {event.src_path}")

class FolderMonitorDevice(BaseDevice):
    def run(self):
        self.running = True
        config = json.load(open(self.config_path))
        folder = config.get("folder_path", str(Path.home()))
        path = Path(folder)
        if not path.exists():
            path.mkdir(parents=True)

        event_handler = FolderEventHandler(self)
        observer = Observer()
        observer.schedule(event_handler, str(path), recursive=False)
        observer.start()
        self.append_log("Started monitoring folder.")

        try:
            while self.running:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()
            self.append_log("Stopped monitoring folder.")
