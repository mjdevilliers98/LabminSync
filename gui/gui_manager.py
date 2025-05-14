from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTabWidget, QLabel, QTextEdit, QHBoxLayout, QMessageBox, QDialog,
    QCheckBox, QLineEdit, QFormLayout
)
from PySide6.QtCore import Qt
import sys

class GUIManager:
    def __init__(self, title, settings, on_start, on_exit):
        self.settings = settings
        self.on_start = on_start
        self.on_exit = on_exit
        self.app = QApplication(sys.argv)
        self.window = QMainWindow()
        self.window.setWindowTitle(title)
        self.tab_widget = QTabWidget()
        self.device_tabs = []

    def build_main_window(self, device_manager):
        central = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(self.tab_widget)

        bottom = QHBoxLayout()
        self.start_btn = QPushButton("Start Devices")
        self.start_btn.clicked.connect(self.on_start)
        bottom.addWidget(self.start_btn)

        self.settings_btn = QPushButton("Settings")
        self.settings_btn.clicked.connect(self.show_settings_window)
        bottom.addWidget(self.settings_btn)

        self.license_btn = QPushButton("License")
        self.license_btn.clicked.connect(self.show_license_window)
        bottom.addWidget(self.license_btn)

        self.exit_btn = QPushButton("Exit")
        self.exit_btn.clicked.connect(self.on_exit)
        bottom.addWidget(self.exit_btn)

        layout.addLayout(bottom)
        central.setLayout(layout)
        self.window.setCentralWidget(central)

    def add_device_tab(self, device_name):
        tab = QWidget()
        layout = QVBoxLayout()
        log_view = QTextEdit()
        log_view.setReadOnly(True)
        layout.addWidget(QLabel(f"Log for {device_name}"))
        layout.addWidget(log_view)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, device_name)
        self.device_tabs.append((device_name, log_view))
        return log_view

    def append_log(self, device_name, message):
        for name, view in self.device_tabs:
            if name == device_name:
                view.append(message)

    def show_error(self, title, message):
        QMessageBox.critical(self.window, title, message)

    def run(self):
        self.window.show()
        self.app.exec()

    def quit(self):
        self.app.quit()

    def show_settings_window(self):
        dialog = QDialog(self.window)
        dialog.setWindowTitle("App Settings")
        layout = QFormLayout()

        launch_startup = QCheckBox()
        launch_startup.setChecked(self.settings.get("launch_on_startup"))
        layout.addRow("Launch on Startup", launch_startup)

        launch_min = QCheckBox()
        launch_min.setChecked(self.settings.get("launch_minimized"))
        layout.addRow("Launch Minimized", launch_min)

        offline = QCheckBox()
        offline.setChecked(self.settings.get("offline_mode"))
        layout.addRow("Offline Mode", offline)

        computer_name = QLineEdit()
        computer_name.setText(self.settings.get("computer_name"))
        layout.addRow("Computer Name", computer_name)

        clip = QCheckBox()
        clip.setChecked(self.settings.get("enable_clipboard"))
        layout.addRow("Enable Clipboard", clip)

        webhook = QCheckBox()
        webhook.setChecked(self.settings.get("enable_webhook"))
        layout.addRow("Enable Webhook", webhook)

        webhook_url = QLineEdit()
        webhook_url.setText(self.settings.get("webhook_url"))
        layout.addRow("Webhook URL", webhook_url)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(lambda: self._save_settings(
            launch_startup.isChecked(), launch_min.isChecked(), offline.isChecked(),
            computer_name.text(), clip.isChecked(), webhook.isChecked(), webhook_url.text(), dialog
        ))
        layout.addRow(save_btn)

        dialog.setLayout(layout)
        dialog.exec_()

    def _save_settings(self, startup, minimized, offline, comp_name, clip, webhook, url, dialog):
        self.settings.set("launch_on_startup", startup)
        self.settings.set("launch_minimized", minimized)
        self.settings.set("offline_mode", offline)
        self.settings.set("computer_name", comp_name)
        self.settings.set("enable_clipboard", clip)
        self.settings.set("enable_webhook", webhook)
        self.settings.set("webhook_url", url)
        dialog.accept()

    def show_license_window(self):
        dialog = QDialog(self.window)
        dialog.setWindowTitle("License")
        layout = QVBoxLayout()

        key_input = QLineEdit()
        key_input.setText("".join(self.settings.get("license_key", "")))
        layout.addWidget(QLabel("License Key"))
        layout.addWidget(key_input)

        save_btn = QPushButton("Save License")
        save_btn.clicked.connect(lambda: (self.settings.set("license_key", key_input.text()), dialog.accept()))
        layout.addWidget(save_btn)

        dialog.setLayout(layout)
        dialog.exec()
