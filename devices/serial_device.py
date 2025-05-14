import time
import json
import serial
from .base_device import BaseDevice

class SerialDevice(BaseDevice):
    def run(self):
        self.running = True
        config = json.load(open(self.config_path))
        try:
            ser = serial.Serial(
                port=config.get("port", "COM1"),
                baudrate=int(config.get("baudrate", 9600)),
                timeout=float(config.get("interval", 1.0))
            )
            self.append_log("Serial port opened.")
            while self.running:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    self.append_log(f"Received: {line}")
                time.sleep(0.1)
            ser.close()
        except Exception as e:
            self.append_log(f"Error: {e}")