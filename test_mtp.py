import time
import win32gui


def get_window():

    hwnd = win32gui.GetForegroundWindow()

    if not hwnd:
        return "", ""

    title = win32gui.GetWindowText(hwnd)

    class_name = win32gui.GetClassName(hwnd)

    return title, class_name


print("=" * 70)
print("FORENSICGUARD MTP EXPLORER TEST")
print("=" * 70)

print("\nOpen:")
print("Phone → Internal shared storage → Project")
print("\nThen perform:")
print("Right-click → Paste")
print("\nWatching Explorer...\n")

last = None

while True:

    try:

        title, class_name = get_window()

        current = (
            title,
            class_name
        )

        if current != last:

            print(
                f"Window : {title}"
            )

            print(
                f"Class  : {class_name}"
            )

            print("-" * 50)

            last = current

        time.sleep(0.1)

    except KeyboardInterrupt:

        print("\nStopped.")

        break