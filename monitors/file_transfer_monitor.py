import os
import time
import string
import threading
from pathlib import Path

import psutil
import win32clipboard
import win32con
import win32gui

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.logger import log_event


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 0.5

CLIPBOARD_RETENTION_SECONDS = 120

TRANSFER_DEDUP_SECONDS = 5


# ============================================================
# GLOBAL STATE
# ============================================================

last_clipboard_files = []

last_clipboard_signature = None

last_clipboard_time = 0

last_transfer_signature = None

last_transfer_time = 0


# ============================================================
# CLIPBOARD
# ============================================================

def get_clipboard_files():

    files = []

    try:

        win32clipboard.OpenClipboard()

        if win32clipboard.IsClipboardFormatAvailable(
            win32con.CF_HDROP
        ):

            files = list(
                win32clipboard.GetClipboardData(
                    win32con.CF_HDROP
                )
            )

        win32clipboard.CloseClipboard()

    except Exception:

        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass

    return files


def get_clipboard_sequence():

    try:
        return win32clipboard.GetClipboardSequenceNumber()

    except Exception:
        return None


def get_stable_clipboard_files():

    previous = None

    for _ in range(8):

        current = tuple(
            sorted(
                get_clipboard_files()
            )
        )

        if current == previous:

            return list(current)

        previous = current

        time.sleep(0.1)

    return (
        list(previous)
        if previous
        else []
    )


# ============================================================
# FILE INFORMATION
# ============================================================

def get_file_size(path):

    try:
        return os.path.getsize(path)

    except (
        FileNotFoundError,
        PermissionError,
        OSError
    ):
        return 0


def get_file_information(files):

    result = []

    for path in files:

        try:

            path = os.path.abspath(path)
            filename = os.path.basename(path).casefold()
            extension = Path(path).suffix.casefold()
            if (
                filename in {"forensic.db", "riskalert.db"}
                or filename.endswith(("-wal", "-shm", "-journal"))
                or extension in {".db", ".sqlite", ".sqlite3"}
            ):
                continue

            result.append({
                "source_path": path,
                "file_name": os.path.basename(path),
                "extension": Path(path).suffix.lower(),
                "file_size": get_file_size(path)
            })

        except Exception:
            continue

    return result


def make_signature(files):

    return tuple(
        sorted(
            os.path.abspath(
                path
            ).lower()
            for path in files
        )
    )


# ============================================================
# ACTIVE WINDOW
# ============================================================

def get_active_window_title():

    try:

        hwnd = (
            win32gui.GetForegroundWindow()
        )

        if not hwnd:
            return ""

        return (
            win32gui.GetWindowText(hwnd)
            or ""
        )

    except Exception:

        return ""


# ============================================================
# USB DEVICE INFORMATION
# ============================================================

def get_usb_device_name():

    try:

        from monitors.usb_monitor import (
            get_usb_devices
        )

        devices = get_usb_devices()

        meaningful = []

        generic = {
            "USB Composite Device",
            "USB Root Hub",
            "USB Hub",
            "ADB Interface",
            "Unknown USB Device"
        }

        for device in devices.values():

            name = (
                device.get("name")
                or ""
            ).strip()

            if (
                name
                and
                name not in generic
            ):

                meaningful.append(
                    name
                )

        if meaningful:

            return meaningful[0]

    except Exception:
        pass

    return "USB Device"


# ============================================================
# REMOVABLE DRIVE DETECTION
# ============================================================

def get_removable_drives():

    drives = set()

    try:

        for partition in (
            psutil.disk_partitions(
                all=False
            )
        ):

            mountpoint = (
                partition.mountpoint
            )

            options = (
                partition.opts
                or ""
            ).lower()

            if "removable" in options:

                drives.add(
                    mountpoint
                )

    except Exception:
        pass

    # --------------------------------------------------------
    # Windows fallback
    # --------------------------------------------------------

    for letter in string.ascii_uppercase:

        drive = f"{letter}:\\"

        if not os.path.exists(drive):
            continue

        try:

            output = os.popen(
                f"fsutil fsinfo drivetype {letter}:"
            ).read().lower()

            if "removable" in output:

                drives.add(
                    drive
                )

        except Exception:
            continue

    return sorted(drives)


# ============================================================
# RECORD FILE COPY
#
# This is generated when the user actually performs Ctrl+C
# / Copy in Windows Explorer.
#
# It records ALL selected files.
# ============================================================

def record_file_copy(files):

    global last_clipboard_files
    global last_clipboard_signature
    global last_clipboard_time

    information = (
        get_file_information(files)
    )

    if not information:
        return

    signature = make_signature(files)

    # --------------------------------------------------------
    # Prevent repeated copies of the same selection.
    # --------------------------------------------------------

    if signature == last_clipboard_signature:

        return

    last_clipboard_files = files

    last_clipboard_signature = signature

    last_clipboard_time = time.time()

    total_size = sum(
        item["file_size"]
        for item in information
    )

    print("\n" + "=" * 75)
    print("FILE COPY DETECTED")
    print("=" * 75)

    print(
        f"Files copied : "
        f"{len(information)}"
    )

    print(
        f"Total size   : "
        f"{total_size} bytes"
    )

    for item in information:

        print(
            f"  - "
            f"{item['file_name']} "
            f"({item['file_size']} bytes)"
        )

    print("=" * 75)

    details = (

        f"FileCount="
        f"{len(information)} | "

        f"TotalSize="
        f"{total_size} bytes | "

        f"FileSizes={','.join(str(item['file_size']) for item in information)} | "

        f"Files="
        +
        " | ".join(
            item["file_name"]
            for item in information
        )
    )

    log_event(

        source="File Transfer Monitor",

        event_id="FILE_COPY",

        action="Files Copied",

        application="Windows Explorer",

        details=details
    )


# ============================================================
# MTP / PHONE DESTINATION DETECTION
# ============================================================

def looks_like_mtp_window(title):

    if not title:
        return False

    text = title.lower()

    indicators = (

        "internal shared storage",

        "phone storage",

        "mobile device",

        "portable device",

        "mtp",

        "android",

        "iphone",

        "ipad",

        "dcim",

        "sd card",

    )

    return any(
        indicator in text
        for indicator in indicators
    )


# ============================================================
# RECORD MTP TRANSFER ATTEMPT
#
# We deliberately use ATTEMPTED / UNVERIFIED because MTP
# does not expose a normal Windows filesystem path.
# ============================================================

def record_mtp_transfer():

    global last_transfer_signature
    global last_transfer_time

    if not last_clipboard_files:

        return

    now = time.time()

    if (
        now - last_clipboard_time
        >
        CLIPBOARD_RETENTION_SECONDS
    ):

        return

    title = (
        get_active_window_title()
    )

    if not looks_like_mtp_window(
        title
    ):

        return

    signature = (
        make_signature(
            last_clipboard_files
        )
    )

    # --------------------------------------------------------
    # Debounce
    # --------------------------------------------------------

    if (
        signature
        ==
        last_transfer_signature
        and
        now - last_transfer_time
        <
        TRANSFER_DEDUP_SECONDS
    ):

        return

    last_transfer_signature = signature

    last_transfer_time = now

    information = (
        get_file_information(
            last_clipboard_files
        )
    )

    if not information:
        return

    total_size = sum(
        item["file_size"]
        for item in information
    )

    device = (
        get_usb_device_name()
    )

    print("\n" + "=" * 75)
    print("MTP FILE TRANSFER ATTEMPT")
    print("=" * 75)

    print(
        f"Device       : {device}"
    )

    print(
        f"Destination  : {title}"
    )

    print(
        f"Files        : "
        f"{len(information)}"
    )

    print(
        f"Total size   : "
        f"{total_size} bytes"
    )

    for item in information:

        print(
            f"  - "
            f"{item['file_name']} "
            f"({item['file_size']} bytes)"
        )

    print(
        "Status       : "
        "ATTEMPTED / UNVERIFIED"
    )

    print("=" * 75)

    details = (

        f"Device={device} | "

        f"Destination={title} | "

        f"FileCount="
        f"{len(information)} | "

        f"TotalSize="
        f"{total_size} bytes | "

        f"Status=ATTEMPTED_UNVERIFIED | "

        f"Files="
        +
        " | ".join(
            item["file_name"]
            for item in information
        )
    )

    log_event(

        source="File Transfer Monitor",

        event_id="MTP_TRANSFER_ATTEMPTED",

        action="File Transfer Attempted",

        application="Windows Explorer",

        details=details
    )


# ============================================================
# NORMAL USB FILE HANDLER
# ============================================================

class USBFileHandler(
    FileSystemEventHandler
):

    def process_file(
        self,
        destination
    ):

        try:

            destination = os.path.abspath(
                destination
            )

            if not os.path.isfile(
                destination
            ):

                return

            file_name = (
                os.path.basename(
                    destination
                )
            )

            time.sleep(0.2)

            size = get_file_size(
                destination
            )

            source = "Unknown"

            for source_file in (
                last_clipboard_files
            ):

                if (
                    os.path.basename(
                        source_file
                    ).lower()
                    ==
                    file_name.lower()
                ):

                    source = source_file

                    break

            print("\n" + "=" * 75)
            print("USB FILE TRANSFER DETECTED")
            print("=" * 75)

            print(
                f"Device      : "
                f"{get_usb_device_name()}"
            )

            print(
                f"File        : "
                f"{file_name}"
            )

            print(
                f"Size        : "
                f"{size} bytes"
            )

            print(
                f"Source      : "
                f"{source}"
            )

            print(
                f"Destination : "
                f"{destination}"
            )

            print(
                "Status      : SUCCESS"
            )

            print("=" * 75)

            log_event(

                source="File Transfer Monitor",

                event_id="USB_FILE_TRANSFER",

                action="File Transferred to USB",

                application="Windows Explorer",

                details=(

                    f"Device="
                    f"{get_usb_device_name()} | "

                    f"File={file_name} | "

                    f"Size={size} bytes | "

                    f"Source={source} | "

                    f"Destination={destination} | "

                    f"Status=SUCCESS"
                )
            )

        except Exception as error:

            print(
                "[File Transfer Monitor] "
                f"USB error: {error}"
            )


    def on_created(
        self,
        event
    ):

        if not event.is_directory:

            self.process_file(
                event.src_path
            )


    def on_moved(
        self,
        event
    ):

        if not event.is_directory:

            self.process_file(
                event.dest_path
            )


# ============================================================
# REMOVABLE DRIVE MONITOR
# ============================================================

def removable_drive_monitor():

    observers = {}

    known_drives = set()

    while True:

        try:

            current_drives = set(
                get_removable_drives()
            )

            # ------------------------------------------------
            # New drives
            # ------------------------------------------------

            for drive in (
                current_drives
                -
                known_drives
            ):

                print(
                    "[File Transfer Monitor] "
                    f"Monitoring USB drive: "
                    f"{drive}"
                )

                handler = (
                    USBFileHandler()
                )

                observer = Observer()

                observer.schedule(
                    handler,
                    drive,
                    recursive=True
                )

                observer.start()

                observers[drive] = (
                    observer
                )

            # ------------------------------------------------
            # Removed drives
            # ------------------------------------------------

            for drive in (
                known_drives
                -
                current_drives
            ):

                observer = observers.pop(
                    drive,
                    None
                )

                if observer:

                    observer.stop()

                    observer.join(
                        timeout=2
                    )

            known_drives = (
                current_drives
            )

            time.sleep(
                POLL_INTERVAL
            )

        except Exception as error:

            print(
                "[File Transfer Monitor] "
                f"Drive monitor error: {error}"
            )

            time.sleep(2)


# ============================================================
# CLIPBOARD MONITOR
# ============================================================

def clipboard_monitor():

    previous_sequence = (
        get_clipboard_sequence()
    )

    while True:

        try:

            current_sequence = (
                get_clipboard_sequence()
            )

            if (
                current_sequence is not None
                and
                current_sequence
                !=
                previous_sequence
            ):

                time.sleep(0.15)

                files = (
                    get_stable_clipboard_files()
                )

                valid_files = [

                    path

                    for path in files

                    if os.path.isfile(path)
                ]

                if valid_files:

                    record_file_copy(
                        valid_files
                    )

                previous_sequence = (
                    current_sequence
                )

            # ------------------------------------------------
            # Expire old clipboard state
            # ------------------------------------------------

            if (
                last_clipboard_files
                and
                time.time()
                -
                last_clipboard_time
                >
                CLIPBOARD_RETENTION_SECONDS
            ):

                # Do NOT reset signature immediately.
                # This prevents repeated events from Explorer.

                pass

            time.sleep(
                POLL_INTERVAL
            )

        except Exception as error:

            print(
                "[File Transfer Monitor] "
                f"Clipboard error: {error}"
            )

            time.sleep(1)


# ============================================================
# MTP PASTE MONITOR
#
# We watch the foreground Explorer window and detect the
# Ctrl+V action without relying on clipboard sequence changes.
# ============================================================

def mtp_paste_monitor():

    ctrl_was_down = False

    while True:

        try:

            # ------------------------------------------------
            # Use Windows API through GetAsyncKeyState.
            #
            # Import lazily so normal clipboard monitoring
            # remains independent.
            # ------------------------------------------------

            import win32api

            ctrl_down = bool(
                win32api.GetAsyncKeyState(
                    win32con.VK_CONTROL
                )
                &
                0x8000
            )

            v_down = bool(
                win32api.GetAsyncKeyState(
                    ord("V")
                )
                &
                0x8000
            )

            # Rising edge of CTRL+V
            if (
                ctrl_down
                and
                v_down
                and
                not ctrl_was_down
            ):

                record_mtp_transfer()

            ctrl_was_down = (
                ctrl_down
                and
                v_down
            )

            time.sleep(
                0.05
            )

        except Exception as error:

            print(
                "[File Transfer Monitor] "
                f"MTP monitor error: {error}"
            )

            time.sleep(1)


# ============================================================
# MAIN MONITOR
# ============================================================

def file_transfer_monitor():

    print(
        "[File Transfer Monitor] Started...\n"
    )

    threading.Thread(
        target=clipboard_monitor,
        daemon=True
    ).start()

    threading.Thread(
        target=removable_drive_monitor,
        daemon=True
    ).start()

    threading.Thread(
        target=mtp_paste_monitor,
        daemon=True
    ).start()

    while True:

        try:

            time.sleep(1)

        except KeyboardInterrupt:

            print(
                "\n[File Transfer Monitor] "
                "Stopped."
            )

            break


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    try:

        file_transfer_monitor()

    except KeyboardInterrupt:

        print(
            "\n[File Transfer Monitor] "
            "Stopped."
        )