from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from gui.gui_manager import GUIManager
from core.settings_manager import SettingsManager
from core.license_manager import LicenseManager
from core.logger import Logger
from devices.device_manager import DeviceManager


class AppController:
    def __init__(self):
        self.base_dir = Path.home() / ".serial_app"
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.logger = Logger(self.base_dir / "app.log")
        self.settings = SettingsManager(self.base_dir / "settings.json")
        self.license_manager = LicenseManager(self.base_dir / "license.json", self.settings)
        self.executor = ThreadPoolExecutor(max_workers=10)

        self.gui = GUIManager(
            title="Labmin Sync – Professional Edition v3.0",
            settings=self.settings,
            on_start=self.start_devices,
            on_exit=self.exit_app
        )

        self.device_manager = DeviceManager(
            base_dir=self.base_dir,
            settings=self.settings,
            logger=self.logger,
            executor=self.executor,
            gui=self.gui
        )

    def run(self):
        if not self.license_manager.verify():
            self.gui.show_error("License Error", "Invalid or missing license. App will exit.")
            self.exit_app()
            return

        self.gui.build_main_window(self.device_manager)
        self.gui.run()

    def start_devices(self):
        self.device_manager.initialize_devices()
        self.device_manager.start_all()

    def exit_app(self):
        self.device_manager.stop_all()
        self.executor.shutdown(wait=False)
        self.gui.quit()
