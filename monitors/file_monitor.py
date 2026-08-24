from fileinput import filename
import os
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.logger import log_event


# ---------- Ignore Lists ----------

IGNORE_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    "node_modules",
    "site-packages",
    ".idea",
    ".vscode",
}

IGNORE_FILES = {
    "forensic.db",
    "forensic.db-journal",
    "desktop.ini",
}

IGNORE_EXTENSIONS = {
    ".tmp",
    ".log",
    ".pyc",
    ".pyd",
    ".cache",
    ".lnk",
}

# Used to suppress duplicate events
recent_events = {}


class FileMonitorHandler(FileSystemEventHandler):

    def should_ignore(self, path):

        path = path.lower()

        # Ignore our own database
        filename = Path(path).name.lower()

        if filename in {
            file.lower()
            for file in IGNORE_FILES
        }:
            return True

        # Ignore folders
        parts = Path(path).parts

        for part in parts:
            if part.lower() in {d.lower() for d in IGNORE_DIRS}:
                return True

        # Ignore extensions
        ext = Path(path).suffix.lower()

        if ext in IGNORE_EXTENSIONS:
            return True

        return False

    def suppress_duplicates(self, path, action):

        key = (path, action)

        now = time.time()

        if key in recent_events:

            if now - recent_events[key] < 1:
                return True

        recent_events[key] = now

        return False

    def handle(self, event_id, action, path, details):

        if self.should_ignore(path):
            return

        if self.suppress_duplicates(path, action):
            return

        log_event(
            source="File Monitor",
            event_id=event_id,
            action=action,
            application=path,
            details=details
        )

    def on_created(self, event):

        if event.is_directory:
            return

        self.handle(
            "FILE_CREATE",
            "File Created",
            event.src_path,
            "User created a file"
        )

    def on_modified(self, event):

        if event.is_directory:
            return

        self.handle(
            "FILE_MODIFY",
            "File Modified",
            event.src_path,
            "File content changed"
        )

    def on_deleted(self, event):

        if event.is_directory:
            return

        self.handle(
            "FILE_DELETE",
            "File Deleted",
            event.src_path,
            "User deleted a file"
        )

    def on_moved(self, event):

        if event.is_directory:
            return

        self.handle(
            "FILE_RENAME",
            "File Renamed",
            event.dest_path,
            f"Old Path : {event.src_path}"
        )


def file_monitor():

    observer = Observer()

    home = Path.home()

    folders = []

    # Desktop
    desktop = home / "OneDrive" / "Desktop"
    if desktop.exists():
        folders.append(str(desktop))
    elif (home / "Desktop").exists():
        folders.append(str(home / "Desktop"))

    # Documents
    docs = home / "OneDrive" / "Documents"
    if docs.exists():
        folders.append(str(docs))
    elif (home / "Documents").exists():
        folders.append(str(home / "Documents"))

    # Downloads
    downloads = home / "Downloads"
    if downloads.exists():
        folders.append(str(downloads))

    # Pictures
    pics = home / "OneDrive" / "Pictures"
    if pics.exists():
        folders.append(str(pics))
    elif (home / "Pictures").exists():
        folders.append(str(home / "Pictures"))

    handler = FileMonitorHandler()

    print("\nMonitoring Folders:\n")

    for folder in folders:

        observer.schedule(
            handler,
            folder,
            recursive=True
        )

        print(folder)

    observer.start()

    print("\nFile Monitor V2 Started...\n")

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()