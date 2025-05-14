from pathlib import Path
import json
from .serial_device import SerialDevice
from .folder_device import FolderMonitorDevice

class DeviceManager:
    def __init__(self, base_dir, settings, logger, executor, gui):
        self.base_dir = base_dir
        self.settings = settings
        self.logger = logger
        self.executor = executor
        self.gui = gui
        self.devices = []

    def initialize_devices(self):
        config_file = self.base_dir / "devices_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            config = {"devices": [{"name": "Device1", "type": "serial", "config": "device1_config.json"}]}
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)

        for dev in config["devices"]:
            dev_path = self.base_dir / dev["config"]
            if dev["type"] == "serial":
                device = SerialDevice(dev["name"], dev_path, self.logger, self.gui)
            else:
                device = FolderMonitorDevice(dev["name"], dev_path, self.logger, self.gui)
            self.devices.append(device)
            device.log_view = self.gui.add_device_tab(dev["name"])

    def start_all(self):
        for device in self.devices:
            self.executor.submit(device.run)

    def stop_all(self):
        for device in self.devices:
            device.stop()