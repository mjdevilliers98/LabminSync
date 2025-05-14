import json
from pathlib import Path

class SettingsManager:
    def __init__(self, path: Path):
        self.path = path
        self.settings = self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path, 'r') as f:
                return json.load(f)
        else:
            default = {
                "launch_on_startup": False,
                "launch_minimized": False,
                "offline_mode": False,
                "computer_name": "MyComputer",
                "enable_clipboard": False,
                "enable_webhook": False,
                "webhook_url": "",
                "license_key": ""
            }
            self._write(default)
            return default

    def _write(self, data):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=4)

    def get(self, key, default=None):
        return self.settings.get(key, default)

    def set(self, key, value):
        self.settings[key] = value
        self._write(self.settings)

    def save(self):
        self._write(self.settings)