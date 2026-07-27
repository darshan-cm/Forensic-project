from pathlib import Path
import os

print("Desktop  :", Path.home() / "Desktop")
print("Documents:", Path.home() / "Documents")
print("Downloads:", Path.home() / "Downloads")
print("Pictures :", Path.home() / "Pictures")

print("\nExists?\n")

print("Desktop  :", os.path.exists(Path.home() / "Desktop"))
print("Documents:", os.path.exists(Path.home() / "Documents"))
print("Downloads:", os.path.exists(Path.home() / "Downloads"))
print("Pictures :", os.path.exists(Path.home() / "Pictures"))