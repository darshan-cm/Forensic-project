import time
import subprocess
import json
import re

from utils.logger import log_event


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 1

GENERIC_NAMES = {
    "USB Composite Device",
    "USB Root Hub",
    "USB Hub",
    "ADB Interface",
    "Unknown USB Device",
}


# ============================================================
# GET RAW USB DEVICES
# ============================================================

def get_raw_usb_devices():

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-CimInstance Win32_PnPEntity |
        Where-Object {
            $_.PNPDeviceID -like 'USB*'
        } |
        Select-Object PNPDeviceID, Name, Status |
        ConvertTo-Json -Compress
        """
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return []

        output = result.stdout.strip()

        if not output:
            return []

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        return data

    except Exception as error:

        print(
            f"[USB Monitor] Detection error: {error}"
        )

        return []


# ============================================================
# GROUP USB DEVICES
# ============================================================

def get_usb_devices():

    raw_devices = get_raw_usb_devices()

    grouped = {}

    for device in raw_devices:

        device_id = device.get("PNPDeviceID")
        name = device.get("Name") or "Unknown USB Device"
        status = device.get("Status") or "Unknown"

        if not device_id:
            continue

        # ----------------------------------------------------
        # Extract Vendor ID
        # ----------------------------------------------------

        vid_match = re.search(
            r"VID_([0-9A-Fa-f]{4})",
            device_id
        )

        if not vid_match:
            continue

        vid = vid_match.group(1).upper()

        # ----------------------------------------------------
        # Extract Product ID
        # ----------------------------------------------------

        pid_match = re.search(
            r"PID_([0-9A-Fa-f]{4})",
            device_id
        )

        pid = (
            pid_match.group(1).upper()
            if pid_match
            else "Unknown"
        )

        # ----------------------------------------------------
        # Group by VID.
        #
        # This handles devices whose PID changes when the
        # phone switches between charging / MTP / ADB.
        # ----------------------------------------------------

        key = vid

        candidate = {
            "name": name,
            "status": status,
            "vid": vid,
            "pid": pid
        }

        if key not in grouped:

            grouped[key] = candidate

        else:

            current = grouped[key]

            current_name = current["name"]

            # Prefer meaningful device names.
            if (
                current_name in GENERIC_NAMES
                and name not in GENERIC_NAMES
            ):
                current["name"] = name

            # Specifically prefer the phone's proper name
            # when Windows exposes it.
            if "OPPO F19 Pro" in name:
                current["name"] = "OPPO F19 Pro"

            current["status"] = status
            current["pid"] = pid

    return grouped


# ============================================================
# GET BEST DEVICE NAME
# ============================================================

def get_best_device_name(vid):

    devices = get_usb_devices()

    device = devices.get(vid)

    if device:
        return device["name"]

    return "USB Device"


# ============================================================
# USB MONITOR
# ============================================================

def usb_monitor():

    print("[USB Monitor] Started...\n")

    previous_devices = get_usb_devices()

    print(
        f"[USB Monitor] Initial USB device groups: "
        f"{len(previous_devices)}"
    )

    while True:

        try:

            current_devices = get_usb_devices()

            # =================================================
            # NEW USB DEVICE
            # =================================================

            connected_ids = (
                set(current_devices)
                -
                set(previous_devices)
            )

            for device_id in connected_ids:

                device = current_devices[device_id]

                # ------------------------------------------------
                # IMMEDIATE EVENT
                # ------------------------------------------------

                print("\n" + "=" * 70)
                print("USB DEVICE CONNECTED")
                print("=" * 70)

                print(
                    f"Device : {device['name']}"
                )

                print(
                    "Status : Connected"
                )

                print(
                    f"VID    : {device['vid']}"
                )

                print(
                    f"PID    : {device['pid']}"
                )

                print("=" * 70)

                log_event(
                    source="USB Monitor",
                    event_id="USB_CONNECTED",
                    action="USB Device Connected",
                    application="Windows",
                    details=(
                        f"Device={device['name']} | "
                        f"Status=Connected | "
                        f"VID={device['vid']} | "
                        f"PID={device['pid']}"
                    )
                )

            # =================================================
            # USB DEVICE REMOVED
            # =================================================

            removed_ids = (
                set(previous_devices)
                -
                set(current_devices)
            )

            for device_id in removed_ids:

                device = previous_devices[device_id]

                print("\n" + "=" * 70)
                print("USB DEVICE REMOVED")
                print("=" * 70)

                print(
                    f"Device : {device['name']}"
                )

                print(
                    "Status : Disconnected"
                )

                print(
                    f"VID    : {device['vid']}"
                )

                print(
                    f"PID    : {device['pid']}"
                )

                print("=" * 70)

                log_event(
                    source="USB Monitor",
                    event_id="USB_REMOVED",
                    action="USB Device Removed",
                    application="Windows",
                    details=(
                        f"Device={device['name']} | "
                        f"Status=Disconnected | "
                        f"VID={device['vid']} | "
                        f"PID={device['pid']}"
                    )
                )

            # ------------------------------------------------
            # Update state
            # ------------------------------------------------

            previous_devices = current_devices

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:

            print(
                "\n[USB Monitor] Stopped."
            )

            break

        except Exception as error:

            print(
                f"[USB Monitor] Error: {error}"
            )

            time.sleep(2)


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    usb_monitor()