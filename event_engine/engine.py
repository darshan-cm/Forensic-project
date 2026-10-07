from queue import Queue
from time import monotonic

event_queue = Queue()


def publish(event):
    """
    Add an event to the central queue.
    """
    event_queue.put(event)


def consume():
    """
    Retrieve the next event.
    """
    return event_queue.get()


def wait_until_idle(timeout=5):
    """Wait for queued event assessments to finish without blocking forever."""
    deadline = monotonic() + timeout
    with event_queue.all_tasks_done:
        while event_queue.unfinished_tasks:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            event_queue.all_tasks_done.wait(remaining)
    return True