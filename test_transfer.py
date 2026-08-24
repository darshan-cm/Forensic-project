import time
import os
import win32clipboard
import win32con


def get_clipboard_files():

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

        else:
            files = []

        win32clipboard.CloseClipboard()

        return files

    except Exception as e:

        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass

        print("Clipboard error:", e)

        return []


print("=" * 70)
print("FORENSICGUARD FILE COPY TEST")
print("=" * 70)

print("\nSelect 3 files in Windows Explorer.")
print("Press CTRL+C.")
print("Waiting for clipboard...\n")

last = None

while True:

    files = get_clipboard_files()

    current = tuple(
        sorted(files)
    )

    if current != last:

        if files:

            print("\nFILES DETECTED:")
            print("-" * 50)

            print(
                "Count:",
                len(files)
            )

            for file in files:

                print(
                    " -",
                    file
                )

            print("-" * 50)

        last = current

    time.sleep(0.5)