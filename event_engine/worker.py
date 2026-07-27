from event_engine.engine import consume
from utils.logger import log_event


def event_worker():

    print("[Event Engine] Started...")

    while True:

        event = consume()

        log_event(event)