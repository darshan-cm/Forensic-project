from event_engine.engine import consume, event_queue


def event_worker():

    print("[Event Engine] Started...")

    # Import risk handler after starting to avoid circular imports
    from detection.event_risk_handler import assess_event

    while True:
        event = consume()
        try:
            # Process event for risk assessment (events from monitors)
            if isinstance(event, dict):
                # Assess risk for this event if it's a trigger type
                assess_event(event)
            else:
                # Legacy support for non-dict events
                pass
        
        except Exception as error:
            print(f"[Event Engine] Worker error: {error}")
        finally:
            event_queue.task_done()