import hashlib
import platform
import uuid
import json
from pathlib import Path

class LicenseManager:
    def __init__(self, license_path: Path, settings_manager):
        self.license_path = license_path
        self.settings = settings_manager

    def verify(self):
        license_data = self._load()
        license_key = license_data.get("license_key", "")
        mac = self._get_mac()
        serial = self._get_serial()
        salt = "Labmin2025"
        local_hash = hashlib.sha256(f"{license_key}{mac}{serial}{salt}".encode()).hexdigest()
        return license_data.get("local_hash") == local_hash

    def _load(self):
        if self.license_path.exists():
            return json.loads(self.license_path.read_text())
        return {}

    def _get_mac(self):
        mac_num = hex(uuid.getnode()).replace('0x', '').upper()
        return ':'.join(mac_num[i:i+2] for i in range(0, 11, 2))

    def _get_serial(self):
        try:
            if platform.system() == 'Windows':
                import subprocess
                result = subprocess.check_output('wmic bios get serialnumber', shell=True).decode()
                return result.strip().split('\n')[-1].strip()
        except:
            return ""
        return ""