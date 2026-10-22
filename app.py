from flask import Flask, jsonify, render_template_string, request
from datetime import datetime
import random
import statistics
import threading
import time
import os
import json
import sqlite3
import secrets

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

try:
    from winotify import Notification, audio
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False

try:
    import serial
    from serial.tools import list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    serial = None
    list_ports = None
    SERIAL_AVAILABLE = False

app = Flask(__name__)

# Safety boundary for endpoints that change simulation state or control a serial port.
# These controls are intended for the local dashboard only. If HOST is configured
# to listen on a non-loopback interface (for example, 0.0.0.0 on a public host),
# all control endpoints fail closed instead of becoming remotely callable.
import ipaddress
from functools import wraps

_CONTROL_PATHS = {
    "/api/test-risk",
    "/api/mode",
    "/api/serial/connect",
    "/api/serial/disconnect",
}

def _is_loopback_address(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except (TypeError, ValueError):
        return False

@app.before_request
def protect_local_control_endpoints():
    if request.path not in _CONTROL_PATHS:
        return None

    configured_host = os.environ.get("HOST", "127.0.0.1").strip().lower()
    # Explicitly refuse control operations when the server is exposed on a
    # network interface. This avoids treating a reverse-proxy deployment as local.
    if configured_host not in {"127.0.0.1", "localhost", "::1"}:
        return jsonify({
            "error": "Control endpoints are disabled when HOST is exposed beyond localhost."
        }), 403

    if not _is_loopback_address(request.remote_addr):
        return jsonify({"error": "This control endpoint is available only from this computer."}), 403

    # Require JSON for state-changing requests, reducing accidental cross-site form posts.
    if request.method == "POST" and not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415

    return None

# This is a LOCAL DEMONSTRATION. It generates simulated sensor readings.
# It does not scan Windows for malware and is not connected to Cirkit/ESP32 yet.
state_lock = threading.Lock()
mode = "normal"
history = []
last_notification_key = None
baseline = {
    "temperature": [24.0, 25.0, 26.0, 25.5, 24.8, 26.2, 25.1, 24.6, 25.7, 24.9],
    "humidity": [50.0, 55.0, 58.0, 52.0, 60.0, 54.0, 57.0, 53.0, 56.0, 51.0],
    "input_proxy": [4.8, 5.2, 5.7, 6.1, 5.0, 5.4, 6.0, 5.5, 4.9, 5.8],
}
baseline_stats = {
    key: (statistics.mean(vals), max(statistics.pstdev(vals), 0.5))
    for key, vals in baseline.items()
}
latest = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "temperature": 25.0,
    "humidity": 55.0,
    "motion": False,
    "input_proxy": 5.3,
    "risk": "NORMAL",
    "reasons": ["Waiting for first simulated sample."],
    "mode": mode,
}
serial_connection = None
serial_thread = None
serial_stop = threading.Event()
serial_write_lock = threading.Lock()
last_hardware_led_command = None
hardware_connected = False
hardware_message = "Simulation mode is active. No hardware is connected."

# Laptop metrics are read from Windows by this Flask process when psutil is installed.
_previous_net = None
_previous_net_time = None
system_notification_key = None


def send_led_command(risk, force=False):
    """Send a text command to a connected ESP32; firmware must support this protocol."""
    global hardware_message, last_hardware_led_command

    normalized = str(risk).strip().upper()
    if normalized not in {"NORMAL", "MEDIUM", "HIGH", "CLEAR"}:
        return {"sent": False, "message": f"Unsupported LED risk command: {normalized}."}

    # ESP32 firmware should read one UTF-8 command per line.
    command = f"risk {normalized.lower()}\n"
    with state_lock:
        connection = serial_connection
        connected = hardware_connected

    if not connected or connection is None:
        return {
            "sent": False,
            "command": command.strip(),
            "message": "Simulation mode only: no ESP32 serial connection, so no physical LED command was sent."
        }

    if not force and last_hardware_led_command == normalized:
        return {
            "sent": True,
            "command": command.strip(),
            "message": f"ESP32 LED command remains {normalized}; no duplicate command needed."
        }

    try:
        with serial_write_lock:
            connection.write(command.encode("utf-8"))
            connection.flush()
        last_hardware_led_command = normalized
        message = f"Sent '{command.strip()}' to the ESP32."
        with state_lock:
            hardware_message = message
        return {"sent": True, "command": command.strip(), "message": message}
    except Exception as exc:
        message = f"Could not send LED command to ESP32: {exc}"
        with state_lock:
            hardware_message = message
        return {"sent": False, "command": command.strip(), "message": message}


def assess_hardware_sample(payload):
    """Validate a JSON line received from an ESP32 and assess its sensor values."""
    global latest
    temperature = float(payload.get("temperature", payload.get("temp", 25.0)))
    humidity = float(payload.get("humidity", 55.0))
    input_proxy = float(payload.get("input_proxy", payload.get("analog", 5.0)))
    raw_motion = payload.get("motion", False)
    if isinstance(raw_motion, str):
        motion = raw_motion.strip().lower() in {"1", "true", "yes", "detected", "on"}
    else:
        motion = bool(raw_motion)

    reasons = []
    risk = "NORMAL"
    if temperature >= 45:
        risk = "HIGH"
        reasons.append(f"Hardware temperature {temperature:.1f}°C reached HIGH threshold (45°C).")
    elif temperature >= 35:
        risk = "MEDIUM"
        reasons.append(f"Hardware temperature {temperature:.1f}°C exceeded MEDIUM threshold (35°C).")
    if input_proxy >= 15:
        risk = "HIGH"
        reasons.append(f"Hardware input value {input_proxy:.2f} reached HIGH threshold (15).")
    elif input_proxy >= 8:
        if risk != "HIGH": risk = "MEDIUM"
        reasons.append(f"Hardware input value {input_proxy:.2f} exceeded MEDIUM threshold (8).")
    if not reasons:
        reasons = ["Hardware readings are within configured demo thresholds."]
    sample = {"timestamp": datetime.now().isoformat(timespec="seconds"),
              "temperature": round(temperature, 1), "humidity": round(humidity, 1),
              "motion": motion, "input_proxy": round(input_proxy, 2),
              "risk": risk, "reasons": reasons, "mode": "hardware", "source": "ESP32 USB Serial"}
    with state_lock:
        latest = sample
        history.append(sample)
        del history[:-30]
    notify_if_needed(risk, reasons)
    # Automatically update the physical LED when the assessed hardware risk changes.
    send_led_command(risk)


def serial_reader_loop(connection):
    global hardware_connected, hardware_message, serial_connection
    while not serial_stop.is_set():
        try:
            line = connection.readline().decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            # ESP32 must print one JSON object per line, e.g. {"temperature":26.1,"humidity":55,"motion":0,"input_proxy":5.2}
            import json
            payload = json.loads(line)
            if isinstance(payload, dict):
                assess_hardware_sample(payload)
                with state_lock:
                    hardware_message = "Connected: receiving ESP32 sensor data."
        except Exception as exc:
            # Ignore non-JSON boot messages; keep listening for valid JSON lines.
            if isinstance(exc, (serial.SerialException, OSError)) if SERIAL_AVAILABLE else False:
                break
    try:
        connection.close()
    except Exception:
        pass
    with state_lock:
        hardware_connected = False
        if serial_connection is connection:
            serial_connection = None
        if not serial_stop.is_set():
            hardware_message = "Serial connection ended. Simulation remains available."


def notify_if_needed(risk, reasons):
    global last_notification_key
    if risk == "NORMAL":
        last_notification_key = None
        return
    key = (risk, "|".join(reasons))
    if key == last_notification_key:
        return
    last_notification_key = key
    if NOTIFICATIONS_AVAILABLE:
        try:
            toast = Notification(
                app_id="SecureMonitor AI",
                title=f"SecureMonitor AI: {risk} risk",
                msg="; ".join(reasons)[:240],
                duration="short",
            )
            toast.set_audio(audio.Default, loop=False)
            toast.show()
        except Exception as exc:
            print("Windows notification could not be displayed:", exc)

def sample_readings():
    """Generate sample sensor data and calculate risk from readings."""
    global latest
    with state_lock:
        current_mode = mode

    temperature = random.uniform(24.0, 27.0)
    humidity = random.uniform(47.0, 64.0)
    input_proxy = random.uniform(4.2, 6.9)
    motion = random.random() < 0.25

    if current_mode == "temperature":
        temperature = random.uniform(39.0, 47.0)
    elif current_mode == "input":
        input_proxy = random.uniform(12.0, 19.0)
    elif current_mode == "combined":
        temperature = random.uniform(39.0, 47.0)
        input_proxy = random.uniform(12.0, 19.0)
    elif current_mode == "medium":
        # Deterministic demonstration: the MEDIUM temperature threshold is crossed.
        temperature = 40.0
        input_proxy = 5.5
    elif current_mode == "high":
        # Deterministic demonstration: the HIGH temperature threshold is crossed.
        temperature = 46.0
        input_proxy = 5.5
    elif current_mode in {"normal", "clear"}:
        # Keep the explicit NORMAL/CLEAR test stable and inside normal limits.
        temperature = 25.0
        humidity = 55.0
        input_proxy = 5.5
        motion = False

    reasons = []
    risk = "NORMAL"

    # Configured safety thresholds, plus a simple baseline deviation check.
    if temperature >= 45.0:
        risk = "HIGH"
        reasons.append(f"Temperature {temperature:.1f}°C reached the HIGH threshold (45°C).")
    elif temperature >= 35.0:
        risk = "MEDIUM"
        reasons.append(f"Temperature {temperature:.1f}°C exceeded the MEDIUM threshold (35°C).")

    if input_proxy >= 15.0:
        risk = "HIGH"
        reasons.append(f"Simulated input proxy {input_proxy:.1f} reached the HIGH threshold (15).")
    elif input_proxy >= 8.0:
        if risk != "HIGH":
            risk = "MEDIUM"
        reasons.append(f"Simulated input proxy {input_proxy:.1f} exceeded the MEDIUM threshold (8).")

    # Preserve baseline-deviation detection for generated anomaly modes. Explicit
    # normal/medium/high/clear test modes stay deterministic for a reliable demo.
    if current_mode not in {"normal", "medium", "high", "clear"}:
        for key, value in (("temperature", temperature), ("humidity", humidity), ("input_proxy", input_proxy)):
            mean, stddev = baseline_stats[key]
            z_score = abs(value - mean) / stddev
            if z_score >= 3.0:
                if risk == "NORMAL":
                    risk = "MEDIUM"
                reasons.append(f"{key.replace('_', ' ').title()} deviated strongly from its learned baseline (z≈{z_score:.1f}).")

    if not reasons:
        reasons = ["Readings are within this demo's configured limits and baseline range."]

    sample = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "temperature": round(temperature, 1),
        "humidity": round(humidity, 1),
        "motion": motion,
        "input_proxy": round(input_proxy, 2),
        "risk": risk,
        "reasons": reasons,
        "mode": current_mode,
    }
    with state_lock:
        latest = sample
        history.append(sample)
        del history[:-30]
    notify_if_needed(risk, reasons)
    return sample

@app.get("/api/system-health")
def api_system_health():
    """Return live laptop health metrics. These are separate from ESP32 sensor readings."""
    global _previous_net, _previous_net_time, system_notification_key

    if not PSUTIL_AVAILABLE:
        return jsonify({
            "available": False,
            "message": "Laptop metrics require psutil. Install it with: py -m pip install psutil",
            "risk": "UNAVAILABLE",
            "reasons": ["Install psutil to read live laptop metrics."]
        })

    try:
        cpu = float(psutil.cpu_percent(interval=None))
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")
        battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
        net = psutil.net_io_counters()
        now = time.monotonic()
        upload_mbps = 0.0
        download_mbps = 0.0
        if _previous_net is not None and _previous_net_time is not None:
            elapsed = max(now - _previous_net_time, 0.001)
            upload_mbps = max(0.0, (net.bytes_sent - _previous_net.bytes_sent) / elapsed / 1_000_000)
            download_mbps = max(0.0, (net.bytes_recv - _previous_net.bytes_recv) / elapsed / 1_000_000)
        _previous_net, _previous_net_time = net, now

        battery_percent = round(battery.percent, 1) if battery else None
        battery_plugged = bool(battery.power_plugged) if battery else None
        reasons = []
        risk = "NORMAL"
        # These are demo alert thresholds, not proof of a cyberattack.
        if cpu >= 90:
            risk = "HIGH"
            reasons.append(f"CPU usage is very high ({cpu:.0f}%; demo HIGH threshold 90%).")
        elif cpu >= 75:
            risk = "MEDIUM"
            reasons.append(f"CPU usage is elevated ({cpu:.0f}%; demo MEDIUM threshold 75%).")
        if memory.percent >= 90:
            risk = "HIGH"
            reasons.append(f"RAM usage is very high ({memory.percent:.0f}%; demo HIGH threshold 90%).")
        elif memory.percent >= 80:
            if risk != "HIGH": risk = "MEDIUM"
            reasons.append(f"RAM usage is elevated ({memory.percent:.0f}%; demo MEDIUM threshold 80%).")
        if disk.percent >= 95:
            risk = "HIGH"
            reasons.append(f"Disk usage is critically high ({disk.percent:.0f}%; demo HIGH threshold 95%).")
        elif disk.percent >= 90:
            if risk != "HIGH": risk = "MEDIUM"
            reasons.append(f"Disk usage is high ({disk.percent:.0f}%; demo MEDIUM threshold 90%).")
        network_total = upload_mbps + download_mbps
        if network_total >= 20:
            if risk != "HIGH": risk = "MEDIUM"
            reasons.append(f"Network traffic is unusually high for this demo ({network_total:.1f} MB/s combined).")
        if battery_percent is not None and battery_percent <= 10 and not battery_plugged:
            reasons.append(f"Battery is low ({battery_percent:.0f}%) and the laptop is not charging.")
        if not reasons:
            reasons = ["Laptop usage is within the configured demo thresholds."]
        elif risk == "NORMAL":
            reasons.insert(0, "A device-health advisory was found; it does not by itself prove a security incident.")

        # Notify once per changed non-normal system-risk state to avoid repeated popups.
        key = (risk, tuple(reasons))
        if risk != "NORMAL" and key != system_notification_key:
            system_notification_key = key
            if NOTIFICATIONS_AVAILABLE:
                try:
                    toast = Notification(
                        app_id="SecureMonitor AI",
                        title=f"SecureMonitor AI: laptop {risk.lower()}",
                        msg="; ".join(reasons)[:240],
                        duration="short",
                    )
                    toast.set_audio(audio.Default, loop=False)
                    toast.show()
                except Exception as exc:
                    print("Windows system-health notification could not be displayed:", exc)
        elif risk == "NORMAL":
            system_notification_key = None

        return jsonify({
            "available": True,
            "message": "Live metrics from this Windows laptop.",
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(float(memory.percent), 1),
            "ram_used_gb": round(memory.used / (1024 ** 3), 1),
            "ram_total_gb": round(memory.total / (1024 ** 3), 1),
            "disk_percent": round(float(disk.percent), 1),
            "disk_free_gb": round(disk.free / (1024 ** 3), 1),
            "battery_percent": battery_percent,
            "battery_plugged": battery_plugged,
            "upload_mbps": round(upload_mbps, 2),
            "download_mbps": round(download_mbps, 2),
            "risk": risk,
            "reasons": reasons,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "notification_support": NOTIFICATIONS_AVAILABLE
        })
    except Exception as exc:
        return jsonify({
            "available": False,
            "message": f"Could not read laptop metrics: {exc}",
            "risk": "UNAVAILABLE",
            "reasons": ["Laptop metrics are currently unavailable."]
        }), 500


@app.get("/api/serial/ports")
def api_serial_ports():
    if not SERIAL_AVAILABLE:
        return jsonify({"available": False, "ports": [], "message": "USB serial support is not installed. Run: py -m pip install pyserial"})
    ports = [{"device": p.device, "description": p.description} for p in list_ports.comports()]
    return jsonify({"available": True, "ports": ports, "message": "Select the ESP32 COM port, if a physical board is connected."})

@app.post("/api/serial/connect")
def api_serial_connect():
    global serial_connection, serial_thread, hardware_connected, hardware_message
    if not SERIAL_AVAILABLE:
        return jsonify({"error": "USB serial support is not installed. Run: py -m pip install pyserial"}), 400
    body = request.get_json(silent=True) or {}
    port = str(body.get("port", "")).strip()
    try:
        baud = int(body.get("baud", 115200))
    except (TypeError, ValueError):
        return jsonify({"error": "Baud rate must be a number."}), 400
    if not port:
        return jsonify({"error": "Choose a COM port first."}), 400
    if baud not in {9600, 19200, 38400, 57600, 115200, 230400}:
        return jsonify({"error": "Choose a supported baud rate."}), 400
    try:
        if serial_connection:
            serial_stop.set()
            try: serial_connection.close()
            except Exception: pass
        connection = serial.Serial(port, baudrate=baud, timeout=1)
        serial_stop.clear()
        serial_connection = connection
        hardware_connected = True
        hardware_message = f"Serial port {port} opened; waiting for valid JSON sensor readings."
        serial_thread = threading.Thread(target=serial_reader_loop, args=(connection,), daemon=True)
        serial_thread.start()
        return jsonify({"connected": True, "message": hardware_message})
    except Exception as exc:
        hardware_connected = False
        hardware_message = f"Could not open {port}: {exc}"
        return jsonify({"error": hardware_message}), 400

@app.post("/api/serial/disconnect")
def api_serial_disconnect():
    global serial_connection, hardware_connected, hardware_message
    serial_stop.set()
    if serial_connection:
        try: serial_connection.close()
        except Exception: pass
    serial_connection = None
    hardware_connected = False
    hardware_message = "Disconnected. Simulation remains available."
    return jsonify({"connected": False, "message": hardware_message})

@app.get("/api/status")
def api_status():
    with state_lock:
        connected = hardware_connected
        message = hardware_message
    sample = None if connected else sample_readings()
    if connected:
        with state_lock:
            sample = dict(latest)
    with state_lock:
        return jsonify({"latest": sample, "history": list(reversed(history[-12:])),
                        "notification_support": NOTIFICATIONS_AVAILABLE,
                        "simulation_only": not connected, "hardware_connected": connected,
                        "hardware_message": message, "serial_available": SERIAL_AVAILABLE})

@app.post("/api/mode")
def api_mode():
    global mode, last_notification_key
    body = request.get_json(silent=True) or {}
    requested = body.get("mode")
    if not isinstance(requested, str):
        return jsonify({"error": "Provide a mode string."}), 400
    requested = requested.strip().lower()
    if requested not in {"normal", "temperature", "input", "combined", "medium", "high", "clear"}:
        return jsonify({"error": "Invalid mode. Use normal, medium, high, clear, temperature, input, or combined."}), 400
    with state_lock:
        mode = requested
        last_notification_key = None
    labels = {
        "normal": "NORMAL test selected; simulated readings are within normal limits.",
        "medium": "MEDIUM risk test selected; temperature is set to 40°C.",
        "high": "HIGH risk test selected; temperature is set to 46°C.",
        "clear": "Manual test cleared; simulated readings returned to normal.",
        "temperature": "Temperature anomaly",
        "input": "Simulated-input anomaly",
        "combined": "Combined unusual behaviour",
    }
    command_risk = {
        "normal": "NORMAL",
        "medium": "MEDIUM",
        "high": "HIGH",
        "clear": "CLEAR",
        "temperature": "MEDIUM",
        "input": "MEDIUM",
        "combined": "HIGH",
    }[mode]
    hardware_command = send_led_command(command_risk, force=True)
    message = labels[mode] + " " + hardware_command["message"]
    return jsonify({
        "mode": mode,
        "message": message,
        "hardware_command": hardware_command
    })

@app.post("/api/test-risk")
def api_test_risk():
    """Convenience endpoint for local Command Prompt risk demonstrations."""
    body = request.get_json(silent=True) or {}
    requested = body.get("risk", body.get("mode", ""))
    if not isinstance(requested, str):
        return jsonify({"error": "Provide risk as normal, medium, high, or clear."}), 400
    requested = requested.strip().lower().replace("risk ", "")
    if requested not in {"normal", "medium", "high", "clear"}:
        return jsonify({"error": "Use risk: normal, medium, high, or clear."}), 400
    global mode, last_notification_key
    with state_lock:
        mode = requested
        last_notification_key = None
    labels = {
        "normal": "NORMAL test selected; simulated readings are within normal limits.",
        "medium": "MEDIUM risk test selected; temperature is set to 40°C.",
        "high": "HIGH risk test selected; temperature is set to 46°C.",
        "clear": "Manual test cleared; simulated readings returned to normal.",
    }
    hardware_command = send_led_command(requested.upper(), force=True)
    message = labels[requested] + " " + hardware_command["message"]
    return jsonify({
        "mode": requested,
        "message": message,
        "hardware_command": hardware_command
    })

@app.get("/")
def index():
    return render_template_string(HTML)

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureMonitor AI | IoT Behaviour Dashboard</title>
<style>
:root{--bg:#0b1220;--panel:#121d31;--panel2:#17253d;--text:#edf4ff;--muted:#9eb0ca;--line:#293a56;--blue:#60a5fa;--green:#34d399;--amber:#fbbf24;--red:#fb7185}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#182c4c 0,#0b1220 45%);color:var(--text);font:15px/1.5 Segoe UI,Arial,sans-serif}
main{max-width:1180px;margin:auto;padding:28px 20px 50px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}
h1{font-size:clamp(25px,4vw,36px);margin:0;letter-spacing:-.6px}.sub{color:var(--muted);margin:6px 0 0}.pill{border:1px solid var(--line);background:#15243a;padding:8px 12px;border-radius:99px;color:#c8d7ee;font-size:13px}
.notice{margin:22px 0;background:#17253d;border:1px solid #365071;border-radius:14px;padding:13px 16px;color:#c8d7ee}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:16px 0}.card{background:linear-gradient(150deg,#15233a,#101a2c);border:1px solid var(--line);border-radius:16px;padding:18px;min-width:0}
.label{color:var(--muted);font-size:13px}.value{font-size:30px;font-weight:700;margin:8px 0 2px}.unit{font-size:14px;color:var(--muted);font-weight:500}.small{color:var(--muted);font-size:12px}
.section{display:grid;grid-template-columns:1.1fr .9fr;gap:14px;margin-top:14px}.risk{display:flex;align-items:center;gap:12px;margin:12px 0 8px}.dot{width:12px;height:12px;border-radius:50%;background:var(--green);box-shadow:0 0 16px currentColor}.risk strong{font-size:25px}.risk.NORMAL{color:var(--green)}.risk.MEDIUM{color:var(--amber)}.risk.HIGH{color:var(--red)}
ul{padding-left:20px;margin:10px 0;color:#e2eaf7}li{margin:7px 0}.buttons{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}button{border:1px solid #3b5273;background:#1b2c46;color:var(--text);padding:10px 13px;border-radius:10px;cursor:pointer;font-weight:600}button:hover{border-color:var(--blue);background:#213858}button.active{background:#1d4b77;border-color:var(--blue)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500}.tag{font-size:11px;font-weight:700;border-radius:99px;padding:4px 8px;background:#1b594b;color:#86efc4}.tag.MEDIUM{background:#614716;color:#fde68a}.tag.HIGH{background:#662d3b;color:#fecdd3}.foot{color:var(--muted);font-size:12px;margin-top:20px}
.system-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:24px}.system-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:12px 0}.system-status{margin-top:12px;padding:12px 14px;border-radius:12px;background:#17253d;border:1px solid var(--line)}.system-status.MEDIUM{border-color:#8a6423}.system-status.HIGH{border-color:#9f344a}.system-status.NORMAL{border-color:#246b58}.metric-value{font-size:25px;font-weight:700;margin:7px 0}.browser-note{color:var(--muted);font-size:12px;margin-top:8px}
@media(max-width:1000px){.system-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:800px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.section{grid-template-columns:1fr}.system-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:430px){.grid{grid-template-columns:1fr 1fr}.value{font-size:25px}main{padding:18px 12px}}
</style>
</head>
<body><main>
<div class="top"><div><h1>SecureMonitor AI</h1><p class="sub">AI-Driven Behavioral Fingerprinting for Real-Time IoT Security and Anomaly Detection</p></div><div class="pill" id="connection">● Starting local demo…</div></div>
<div class="notice" id="sourceNotice"><b>Simulation mode:</b> Readings are generated by this local app. Cirkit Designer simulation does not automatically create a USB COM port. A physical ESP32 or serial bridge is needed for USB readings. “Input proxy” is an uncalibrated value, not real current.</div>
<div class="card" style="margin:16px 0">
  <div class="label">ESP32 Hardware Connection</div>
  <h2 style="margin:6px 0 4px;font-size:20px">USB Serial</h2>
  <p class="small" id="hardwareStatus">Checking serial support…</p>
  <div class="buttons" style="align-items:center">
    <select id="serialPort" style="min-width:180px;max-width:100%;border:1px solid #3b5273;background:#1b2c46;color:var(--text);padding:10px;border-radius:10px"><option value="">Select COM port</option></select>
    <select id="baudRate" style="border:1px solid #3b5273;background:#1b2c46;color:var(--text);padding:10px;border-radius:10px"><option>115200</option><option>9600</option><option>57600</option><option>38400</option><option>19200</option></select>
    <button id="refreshPorts">Refresh ports</button><button id="connectHardware">Connect</button><button id="disconnectHardware">Disconnect</button>
  </div>
  <p class="small">Expected ESP32 serial format: one JSON object per line, for example: {&quot;temperature&quot;:26.1,&quot;humidity&quot;:55,&quot;motion&quot;:0,&quot;input_proxy&quot;:5.2}. USB serial works with a physical ESP32; Cirkit simulation alone may not expose a COM port.</p>
</div>
<div class="grid">
<div class="card"><div class="label">Temperature</div><div class="value" id="temp">-- <span class="unit">°C</span></div><div class="small">Demo threshold: 35°C / 45°C</div></div>
<div class="card"><div class="label">Humidity</div><div class="value" id="humidity">-- <span class="unit">%</span></div><div class="small">Simulated sensor value</div></div>
<div class="card"><div class="label">Input proxy</div><div class="value" id="input">--</div><div class="small">Demo threshold: 8 / 15</div></div>
<div class="card"><div class="label">Motion sensor</div><div class="value" id="motion">--</div><div class="small">Informational only in this demo</div></div>
</div>
<div class="system-head"><div><h2 style="margin:0;font-size:22px">Laptop System Health</h2><p class="sub">Live Windows metrics · separate from ESP32 sensor readings</p></div><button id="enableBrowserNotifications">Enable browser notifications</button></div>
<div class="system-grid">
  <div class="card"><div class="label">Battery</div><div class="metric-value" id="batteryValue">Checking…</div><div class="small" id="batteryDetail">Laptop battery status</div></div>
  <div class="card"><div class="label">CPU usage</div><div class="metric-value" id="cpuValue">--</div><div class="small">Demo alert: 75% / 90%</div></div>
  <div class="card"><div class="label">RAM usage</div><div class="metric-value" id="ramValue">--</div><div class="small" id="ramDetail">Demo alert: 80% / 90%</div></div>
  <div class="card"><div class="label">Disk usage (C:)</div><div class="metric-value" id="diskValue">--</div><div class="small" id="diskDetail">Demo alert: 90% / 95%</div></div>
  <div class="card"><div class="label">Network activity</div><div class="metric-value" id="networkValue">--</div><div class="small" id="networkDetail">Upload / download</div></div>
</div>
<div class="system-status NORMAL" id="systemStatus"><b id="systemRisk">Laptop health: checking…</b><ul id="systemReasons"><li>Waiting for laptop metrics.</li></ul><div class="browser-note" id="systemMessage">Metrics are read locally. High usage is a device-health signal, not proof of a cyberattack.</div></div>
<div class="section">
<div class="card"><div class="label">Current security assessment</div><div class="risk NORMAL" id="riskbox"><span class="dot"></span><strong id="risk">NORMAL</strong></div><div class="small" id="timestamp">Waiting for data…</div><ul id="reasons"><li>Waiting for first sample.</li></ul><div class="label" style="margin-top:18px">Test risk behaviour</div><div class="buttons"><button class="active" data-mode="normal">NORMAL</button><button data-mode="medium">MEDIUM</button><button data-mode="high">HIGH</button><button data-mode="clear">CLEAR</button></div><div class="label" style="margin-top:12px">Additional anomaly scenarios</div><div class="buttons"><button data-mode="temperature">Temperature anomaly</button><button data-mode="input">Input anomaly</button><button data-mode="combined">Combined anomaly</button></div><p class="small">NORMAL, MEDIUM, HIGH and CLEAR use predictable simulated readings for demonstrations. When a physical ESP32 is connected, these controls send line commands (risk normal / risk medium / risk high / risk clear) over USB serial. The ESP32 firmware must implement the same command protocol. Cirkit simulation alone may not expose a Windows COM port.</p></div>
<div class="card"><div class="label">Recent samples</div><table><thead><tr><th>Time</th><th>Temp</th><th>Input</th><th>Risk</th></tr></thead><tbody id="history"><tr><td colspan="4">Collecting samples…</td></tr></tbody></table><p class="small">Up to 12 recent samples; refreshes automatically.</p></div>
</div>
<div class="foot">Local development dashboard · Keep this terminal running while viewing the site. Close it with Ctrl+C when finished.</div>
</main>
<script>
const $=id=>document.getElementById(id);
async function setMode(mode){
  try{
    const r=await fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});
    const d=await r.json();
    if(!r.ok) throw Error(d.error||'Could not change test mode');
    document.querySelectorAll('button[data-mode]').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode));
    $('hardwareStatus').textContent=d.message||'Test mode updated.';
  }catch(e){$('connection').textContent='● Connection issue';$('hardwareStatus').textContent='Could not change mode: '+e.message;}
}
document.querySelectorAll('button[data-mode]').forEach(b=>b.addEventListener('click',()=>setMode(b.dataset.mode)));
function escapeText(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function refreshPorts(){
 try{
  const r=await fetch('/api/serial/ports');const data=await r.json();
  const sel=$('serialPort');sel.innerHTML='<option value="">Select COM port</option>';
  (data.ports||[]).forEach(p=>{const o=document.createElement('option');o.value=p.device;o.textContent=p.device+' — '+p.description;sel.appendChild(o);});
  $('hardwareStatus').textContent=data.message+(data.ports&&data.ports.length?' Found '+data.ports.length+' port(s).':'');
 }catch(e){$('hardwareStatus').textContent='Could not check serial ports.';}
}
$('refreshPorts').addEventListener('click',refreshPorts);
$('connectHardware').addEventListener('click',async()=>{
 try{const r=await fetch('/api/serial/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:$('serialPort').value,baud:Number($('baudRate').value)})});const d=await r.json();$('hardwareStatus').textContent=d.message||d.error;}
 catch(e){$('hardwareStatus').textContent='Could not connect to serial port.';}
});
$('disconnectHardware').addEventListener('click',async()=>{
 try{const r=await fetch('/api/serial/disconnect',{method:'POST'});const d=await r.json();$('hardwareStatus').textContent=d.message;}
 catch(e){$('hardwareStatus').textContent='Could not disconnect serial port.';}
});
let previousSystemRisk='NORMAL';
$('enableBrowserNotifications').addEventListener('click',async()=>{
  if(!('Notification' in window)){ $('systemMessage').textContent='This browser does not support notifications.'; return; }
  const permission=await Notification.requestPermission();
  $('systemMessage').textContent=permission==='granted'?'Browser notifications enabled while this dashboard is open.': 'Notification permission was not granted.';
});
async function updateSystemHealth(){
 try{
  const r=await fetch('/api/system-health');const d=await r.json();
  if(!d.available){
    $('batteryValue').textContent='Unavailable';$('cpuValue').textContent='--';$('ramValue').textContent='--';$('diskValue').textContent='--';$('networkValue').textContent='--';
    $('systemRisk').textContent='Laptop health: unavailable';$('systemReasons').innerHTML='<li>'+escapeText(d.message||'Install psutil to enable laptop metrics.')+'</li>';
    $('systemStatus').className='system-status NORMAL';$('systemMessage').textContent='To enable: stop the app, run py -m pip install psutil in Command Prompt, then restart app.py.';
    return;
  }
  $('cpuValue').textContent=d.cpu_percent.toFixed(1)+'%';
  $('ramValue').textContent=d.ram_percent.toFixed(1)+'%';
  $('ramDetail').textContent=d.ram_used_gb+' / '+d.ram_total_gb+' GB used · demo alert: 80% / 90%';
  $('diskValue').textContent=d.disk_percent.toFixed(1)+'%';
  $('diskDetail').textContent=d.disk_free_gb+' GB free · demo alert: 90% / 95%';
  $('networkValue').textContent=(d.upload_mbps+d.download_mbps).toFixed(2)+' MB/s';
  $('networkDetail').textContent='↑ '+d.upload_mbps.toFixed(2)+' · ↓ '+d.download_mbps.toFixed(2)+' MB/s';
  if(d.battery_percent===null){$('batteryValue').textContent='Not detected';$('batteryDetail').textContent='Desktop or battery sensor unavailable';}
  else{$('batteryValue').textContent=d.battery_percent.toFixed(0)+'%';$('batteryDetail').textContent=(d.battery_plugged?'Charging / plugged in':'Discharging / unplugged');}
  $('systemRisk').textContent='Laptop health: '+d.risk;
  $('systemStatus').className='system-status '+d.risk;
  $('systemReasons').innerHTML=d.reasons.map(x=>'<li>'+escapeText(x)+'</li>').join('');
  $('systemMessage').textContent=d.message+' High usage alone does not confirm a cyberattack.';
  if(d.risk!=='NORMAL' && d.risk!=='UNAVAILABLE' && d.risk!==previousSystemRisk && 'Notification' in window && Notification.permission==='granted'){
    new Notification('SecureMonitor AI: laptop '+d.risk.toLowerCase(),{body:d.reasons.join(' ').slice(0,220)});
  }
  previousSystemRisk=d.risk;
 }catch(e){$('systemMessage').textContent='Could not refresh laptop metrics.';}
}
async function update(){
 try{
  const r=await fetch('/api/status');const data=await r.json();const s=data.latest;
  $('connection').textContent=data.hardware_connected?'● ESP32 serial connected':'● Local app connected';
  $('hardwareStatus').textContent=data.hardware_message;
  $('sourceNotice').innerHTML=data.hardware_connected?'<b>Hardware mode:</b> Showing readings received over USB serial from the connected ESP32.':'<b>Simulation mode:</b> Readings are generated by this local app. Cirkit Designer simulation does not automatically create a USB COM port. A physical ESP32 or serial bridge is needed for USB readings. “Input proxy” is an uncalibrated value, not real current.';
  $('temp').innerHTML=`${s.temperature.toFixed(1)} <span class="unit">°C</span>`;
  $('humidity').innerHTML=`${s.humidity.toFixed(1)} <span class="unit">%</span>`;
  $('input').textContent=s.input_proxy.toFixed(2);$('motion').textContent=s.motion?'DETECTED':'Cleared';
  $('risk').textContent=s.risk;$('riskbox').className='risk '+s.risk;
  $('timestamp').textContent='Last sample: '+new Date(s.timestamp).toLocaleString();
  $('reasons').innerHTML=s.reasons.map(x=>'<li>'+escapeText(x)+'</li>').join('');
  $('history').innerHTML=data.history.map(x=>`<tr><td>${new Date(x.timestamp).toLocaleTimeString()}</td><td>${x.temperature.toFixed(1)}°</td><td>${x.input_proxy.toFixed(1)}</td><td><span class="tag ${x.risk}">${x.risk}</span></td></tr>`).join('');
 }catch(e){$('connection').textContent='● Reconnecting…';}
}
refreshPorts();update();updateSystemHealth();setInterval(update,2000);setInterval(updateSystemHealth,3000);
</script></body></html>"""



# ---- Optional remote-device monitoring (requires explicit server-side secrets) ----
# Configure SECUREMONITOR_ADMIN_TOKEN and SECUREMONITOR_DEVICE_TOKENS in the hosting
# provider's environment settings. Never commit those values to source control.
REMOTE_DB = os.environ.get("SECUREMONITOR_DB", os.path.join(os.path.dirname(__file__), "securemonitor_remote.sqlite3"))

def _remote_device_tokens():
    try:
        value = json.loads(os.environ.get("SECUREMONITOR_DEVICE_TOKENS", "{}"))
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}

def _remote_db():
    connection = sqlite3.connect(REMOTE_DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS device_samples (
        device_id TEXT PRIMARY KEY, received_at TEXT NOT NULL, payload TEXT NOT NULL
    )""")
    return connection

def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return ""
    return header[7:].strip()

def _require_admin():
    expected = os.environ.get("SECUREMONITOR_ADMIN_TOKEN", "")
    supplied = _bearer_token()
    return bool(expected) and bool(supplied) and secrets.compare_digest(expected, supplied)

@app.post("/api/remote/ingest")
def api_remote_ingest():
    """Receive consent-based metrics from an installed monitoring agent."""
    supplied = _bearer_token()
    tokens = _remote_device_tokens()
    device_id = next((name for name, token in tokens.items()
                      if isinstance(name, str) and isinstance(token, str) and token
                      and supplied and secrets.compare_digest(token, supplied)), None)
    if not device_id:
        return jsonify({"error": "Invalid device credentials."}), 401
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Expected a JSON object."}), 400
    fields = ("cpu_percent", "ram_percent", "disk_percent", "upload_mbps", "download_mbps")
    try:
        metrics = {key: float(body[key]) for key in fields}
        battery = body.get("battery_percent")
        metrics["battery_percent"] = None if battery is None else float(battery)
        metrics["battery_plugged"] = body.get("battery_plugged") if isinstance(body.get("battery_plugged"), bool) else None
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Missing or invalid metric fields."}), 400
    for key in fields:
        if not (0 <= metrics[key] <= (100 if key in ("cpu_percent", "ram_percent", "disk_percent") else 100000)):
            return jsonify({"error": f"Metric out of range: {key}."}), 400
    if metrics["battery_percent"] is not None and not 0 <= metrics["battery_percent"] <= 100:
        return jsonify({"error": "battery_percent must be between 0 and 100."}), 400
    # Device identity is taken from the authenticated token mapping, not from client input.
    payload = {**metrics, "risk": str(body.get("risk", "UNAVAILABLE"))[:16],
               "reasons": [str(x)[:180] for x in body.get("reasons", [])[:8]] if isinstance(body.get("reasons", []), list) else [],
               "agent_time": str(body.get("timestamp", ""))[:40]}
    received = datetime.now().isoformat(timespec="seconds")
    try:
        with _remote_db() as db:
            db.execute("INSERT INTO device_samples(device_id, received_at, payload) VALUES(?,?,?) "
                       "ON CONFLICT(device_id) DO UPDATE SET received_at=excluded.received_at, payload=excluded.payload",
                       (device_id, received, json.dumps(payload)))
    except sqlite3.Error:
        app.logger.exception("Remote metrics storage failed")
        return jsonify({"error": "Could not store metrics."}), 500
    return jsonify({"ok": True, "device_id": device_id, "received_at": received})

@app.get("/api/remote/devices")
def api_remote_devices():
    if not _require_admin():
        return jsonify({"error": "Dashboard authentication failed."}), 401
    try:
        with _remote_db() as db:
            rows = db.execute("SELECT device_id, received_at, payload FROM device_samples ORDER BY device_id").fetchall()
        devices = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (ValueError, TypeError):
                payload = {}
            devices.append({"device_id": row["device_id"], "received_at": row["received_at"], **payload})
        return jsonify({"devices": devices, "count": len(devices)})
    except sqlite3.Error:
        app.logger.exception("Remote metrics query failed")
        return jsonify({"error": "Could not load device metrics."}), 500

@app.get("/remote")
def remote_dashboard():
    return render_template_string(REMOTE_HTML)

REMOTE_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureMonitor AI | Remote Devices</title>
<style>body{margin:0;background:#0b1220;color:#edf4ff;font:15px/1.5 Segoe UI,Arial,sans-serif}main{max-width:1100px;margin:auto;padding:26px 18px}h1{margin:0}p{color:#9eb0ca}.panel{background:#121d31;border:1px solid #293a56;border-radius:14px;padding:18px;margin:16px 0}input,button{padding:11px;border-radius:8px;border:1px solid #3b5273;background:#17253d;color:#edf4ff}button{cursor:pointer;background:#1d4b77}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #293a56;vertical-align:top}th{color:#9eb0ca}.risk{font-weight:700}.HIGH{color:#fb7185}.MEDIUM{color:#fbbf24}.NORMAL{color:#34d399}.muted{color:#9eb0ca;font-size:13px}.scroll{overflow-x:auto}</style></head><body><main><h1>SecureMonitor AI — Remote Devices</h1><p>View metrics sent by monitoring agents installed with each device owner's permission.</p>
<div class="panel"><label for="token">Dashboard access token</label><br><input id="token" type="password" autocomplete="off" placeholder="Paste admin token" style="width:min(520px,90%);margin:8px 0"><button id="load">Load devices</button><button id="clear">Clear token</button><p class="muted">The token stays in this page's memory and is not saved. Use HTTPS on a deployed site. Do not share this admin token.</p><div id="status" role="status">Enter the admin token to view connected devices.</div></div>
<div class="panel"><h2>Connected devices</h2><div class="scroll"><table><thead><tr><th>Device</th><th>Last received</th><th>CPU</th><th>RAM</th><th>Disk</th><th>Network</th><th>Battery</th><th>Risk</th><th>Reasons</th></tr></thead><tbody id="rows"><tr><td colspan="9">No data loaded.</td></tr></tbody></table></div></div>
<p class="muted">Risk values are usage-based advisories, not proof of malware or a cyberattack. Devices may go offline; “last received” shows the most recent update.</p><p><a href="/" style="color:#60a5fa">Return to local dashboard</a></p></main>
<script>const $=id=>document.getElementById(id);function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}async function load(){const token=$('token').value.trim();if(!token){$('status').textContent='Enter the admin token first.';return;} $('status').textContent='Loading…';try{const r=await fetch('/api/remote/devices',{headers:{Authorization:'Bearer '+token}});const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');$('status').textContent=d.count+' device(s) found.';$('rows').innerHTML=d.devices.length?d.devices.map(x=>`<tr><td>${esc(x.device_id)}</td><td>${esc(x.received_at)}</td><td>${Number(x.cpu_percent).toFixed(1)}%</td><td>${Number(x.ram_percent).toFixed(1)}%</td><td>${Number(x.disk_percent).toFixed(1)}%</td><td>↑ ${Number(x.upload_mbps).toFixed(2)} / ↓ ${Number(x.download_mbps).toFixed(2)} MB/s</td><td>${x.battery_percent==null?'N/A':Number(x.battery_percent).toFixed(0)+'%'}${x.battery_plugged===true?' (charging)':x.battery_plugged===false?' (not charging)':''}</td><td class="risk ${esc(x.risk)}">${esc(x.risk)}</td><td>${(x.reasons||[]).map(esc).join('<br>')||'No reason supplied'}</td></tr>`).join(''):'<tr><td colspan="9">No agents have sent data yet.</td></tr>';}catch(e){$('status').textContent='Could not load devices: '+e.message;$('rows').innerHTML='<tr><td colspan="9">Check the token and server configuration.</td></tr>';}}$('load').addEventListener('click',load);$('clear').addEventListener('click',()=>{$('token').value='';$('rows').innerHTML='<tr><td colspan="9">Token cleared.</td></tr>';$('status').textContent='Token cleared.';});</script></body></html>"""


if __name__ == "__main__":
    print("SecureMonitor AI website starting.")
    print("Simulation is the default. USB serial requires pyserial and a physical ESP32 COM port.")
    print("Cirkit simulation is not automatically connected over USB.")
    print("Windows notifications:", "enabled" if NOTIFICATIONS_AVAILABLE else "unavailable (install winotify)")
    print("Open http://127.0.0.1:5000 in Chrome.")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False, threaded=True)
