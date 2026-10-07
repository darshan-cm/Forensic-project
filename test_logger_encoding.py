import io
import unittest
from unittest.mock import patch

from utils import logger


class Cp1252Output:
    encoding = "cp1252"

    def __init__(self):
        self.output = io.StringIO()

    def write(self, message):
        message.encode(self.encoding)
        return self.output.write(message)


class LoggerEncodingTests(unittest.TestCase):
    def test_unicode_event_text_is_safe_on_cp1252_console(self):
        console = Cp1252Output()
        with (
            patch("utils.logger.sys.stdout", console),
            patch("utils.logger.insert_event", return_value=12) as insert_event,
            patch("event_engine.engine.publish"),
        ):
            logger.log_event(
                source="Active Window",
                event_id="WINDOW_CHANGE",
                action="Window Changed",
                application="● ForensicGuard",
                details="Unicode console regression test",
            )

        insert_event.assert_called_once_with(
            "Active Window",
            "WINDOW_CHANGE",
            "Window Changed",
            "● ForensicGuard",
            "Unicode console regression test",
        )
        self.assertIn(r"\u25cf ForensicGuard", console.output.getvalue())


if __name__ == "__main__":
    unittest.main()
