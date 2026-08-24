import os
import sys
import subprocess


class MonitorController:

    def __init__(self):
        self.process = None

    def start(self):

        if self.process and self.process.poll() is None:
            return False

        project_root = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )

        main_path = os.path.join(
            project_root,
            "main.py"
        )

        self.process = subprocess.Popen(
            [sys.executable, main_path],
            cwd=project_root
        )

        return True

    def stop(self):

        if not self.process:
            return

        if self.process.poll() is None:

            self.process.terminate()

            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()

        self.process = None

    def is_running(self):

        return (
            self.process is not None
            and self.process.poll() is None
        )