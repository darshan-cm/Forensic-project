from queue import Queue

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