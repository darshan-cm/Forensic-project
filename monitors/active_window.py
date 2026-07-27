import time
import win32gui

from utils.logger import log_event


def active_window_monitor():

    print("[Active Window Monitor] Started...\n")

    previous_window = ""

    while True:

        hwnd = win32gui.GetForegroundWindow()

        title = win32gui.GetWindowText(hwnd).strip()

        if title and title != previous_window:

            previous_window = title

            log_event(
                source="Active Window",
                event_id="WINDOW_CHANGE",
                action="Window Changed",
                application=title,
                details="User switched active window"
            )

        time.sleep(1)