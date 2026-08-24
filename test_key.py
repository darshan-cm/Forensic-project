import time
import win32api
import win32con

print("Press CTRL+V several times.")
print("Press CTRL+C in this terminal to stop.\n")

previous = False

while True:

    ctrl = bool(
        win32api.GetAsyncKeyState(
            win32con.VK_CONTROL
        ) & 0x8000
    )

    v = bool(
        win32api.GetAsyncKeyState(
            ord("V")
        ) & 0x8000
    )

    pressed = ctrl and v

    if pressed and not previous:

        print(">>> CTRL+V DETECTED <<<")

    previous = pressed

    time.sleep(0.01)