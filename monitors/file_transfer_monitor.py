import time
from pathlib import Path

import win32clipboard
import win32con

from utils.logger import log_event


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

    for _ in range(10):

        current = tuple(
            sorted(get_clipboard_files())
        )

        if current == previous:
            return list(current)

        previous = current

        time.sleep(0.2)

    return list(previous) if previous else []


def file_transfer_monitor():

    previous_sequence = get_clipboard_sequence()

    print("[File Transfer Monitor] Started...\n")

    while True:

        current_sequence = get_clipboard_sequence()

        # Clipboard changed
        if (
            current_sequence is not None
            and current_sequence != previous_sequence
        ):

            # Give Windows Explorer time to finish
            # putting all selected files into clipboard.
            time.sleep(0.5)

            files = get_stable_clipboard_files()

            valid_files = [
                path
                for path in files
                if Path(path).is_file()
            ]

            if valid_files:

                print("\n" + "=" * 70)
                print("FILE COPY DETECTED")
                print(f"Files copied: {len(valid_files)}")

                for path in sorted(valid_files):
                    print(f"  - {path}")

                print("=" * 70)

                log_event(
                    source="File Transfer Monitor",
                    event_id="FILE_COPY",
                    action="Files Copied",
                    application="Windows Explorer",
                    details=(
                        f"{len(valid_files)} file(s) copied: "
                        + " | ".join(
                            sorted(valid_files)
                        )
                    )
                )

            previous_sequence = current_sequence

        time.sleep(0.2)