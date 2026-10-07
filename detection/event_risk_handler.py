"""
Event-driven risk assessment handler.

This module bridges monitoring events to the risk assessment pipeline.
When file transfer or other high-risk events are detected, this handler
automatically triggers risk assessment without waiting for manual GUI refresh.

This keeps the architecture modular:
- Monitors remain responsible for detection only
- This handler bridges events to risk assessment
- GUI refresh remains for periodic updates and display
- AlertManager handles notification logic

Thread-safe with deduplication to prevent re-assessing the same event.
"""

import time
import threading
from datetime import datetime
from threading import Lock

from detection.risk_engine import assess_risk
from database.riskalert_db import record_risk_assessment
from alerts.alert_manager import AlertManager


# ============================================================================
# EVENT-BASED RISK ASSESSMENT HANDLER
# ============================================================================

class EventRiskHandler:
    """
    Handles automatic risk assessment when certain events occur.
    
    Prevents duplicate assessments through time-based debouncing and 
    event type tracking.
    """

    def __init__(self, debounce_seconds=2):
        """
        Initialize the handler.
        
        Args:
            debounce_seconds: Minimum time between assessments (default 2s)
        """
        self.debounce_seconds = debounce_seconds
        self.last_assessment_time = 0
        self.last_assessment_type = None
        self.lock = Lock()
        self.alert_manager = AlertManager()
        
        # Events that should trigger automatic risk assessment
        self.trigger_events = {
            "FILE_COPY",
            "USB_FILE_TRANSFER",
            "MTP_TRANSFER_ATTEMPTED",
            "USB_CONNECTED",
            "FILE_CREATE",
            "FILE_MODIFY",
            "FILE_DELETE",
            "FILE_RENAME",
            "FOLDER_CREATE",
            "FOLDER_DELETE",
        }
        self.last_file_modification_rule_time = 0
        self.last_new_rule_times = {}

    def should_assess(self, event_id):
        """
        Determine if we should perform risk assessment for this event.
        
        Returns True if:
        - Event type is a trigger event AND
        - Enough time has passed since last assessment (debounce)
        
        Args:
            event_id: The event ID type (FILE_COPY, USB_FILE_TRANSFER, etc.)
            
        Returns:
            Boolean indicating whether to assess
        """
        if event_id not in self.trigger_events:
            return False

        if event_id in {
            "FILE_CREATE",
            "FILE_MODIFY",
            "FILE_DELETE",
            "FILE_RENAME",
            "FOLDER_CREATE",
            "FOLDER_DELETE",
        }:
            return True
        
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_assessment_time
            
            # Debounce: only assess if enough time has passed
            if time_since_last >= self.debounce_seconds:
                return True
            
            return False

    def handle_event(self, event_dict):
        """
        Process a monitoring event and trigger risk assessment if appropriate.
        
        Args:
            event_dict: Dictionary with keys:
                - event_id: Type of event (FILE_COPY, USB_FILE_TRANSFER, etc.)
                - timestamp: When event occurred
                - source: Source module (File Transfer Monitor, etc.)
                - action: Action description
                - application: Application involved
                - details: Event details
        
        Returns:
            The risk assessment result, or None if not assessed
        """
        if not event_dict:
            return None
        
        event_id = event_dict.get("event_id", "")
        
        # Check if we should assess this event
        if not self.should_assess(event_id):
            return None
        
        # Perform risk assessment
        try:
            result = assess_risk(event_dict)
            
            # Record the assessment
            self._record_and_notify(result, event_dict)
            
            # Track that we've assessed
            with self.lock:
                if event_id not in {
                    "FILE_CREATE",
                    "FILE_MODIFY",
                    "FILE_DELETE",
                    "FILE_RENAME",
                    "FOLDER_CREATE",
                    "FOLDER_DELETE",
                }:
                    self.last_assessment_time = time.time()
                    self.last_assessment_type = event_id
            
            return result
            
        except Exception as error:
            print(f"[Event Risk Handler] Assessment failed: {error}")
            return None

    def _record_and_notify(self, risk_result, event_dict):
        """
        Record the risk assessment and trigger notifications.
        
        Args:
            risk_result: Output from assess_risk()
            event_dict: The triggering event
        """
        if not risk_result:
            return
        
        try:
            risk_level = risk_result.get("risk", "LOW")
            risk_score = risk_result.get("score", 0)
            event_id = str(event_dict.get("event_id", "")).upper()
            lock = getattr(self, "lock", None) or Lock()
            
            # Process notification (handles anti-spam internally)
            notification_triggered = False
            notification_status = "not_required"
            alert_message = None
            
            if event_id not in {
                "FILE_CREATE",
                "FILE_DELETE",
                "FILE_RENAME",
                "FOLDER_CREATE",
                "FOLDER_DELETE",
            }:
                try:
                    notification_triggered = self.alert_manager.process_risk(
                        risk_level,
                        risk_score,
                        risk_result.get("evidence", [])
                    )

                    if risk_level in ("HIGH", "CRITICAL"):
                        notification_status = (
                            "sent" if notification_triggered else "suppressed"
                        )
                        alert_message = (
                            f"{risk_level} risk detected. Score: {risk_score}/100."
                        )

                except Exception as error:
                    print(f"[Alert Manager] {error}")
            
            # Record to risk audit database
            try:
                triggered_rules = risk_result.get("triggered_rules", [])
                event_id = str(event_dict.get("event_id", "")).upper()
                rule_event_ids = {
                    "FILE_COPY",
                    "FILE_CREATE",
                    "FILE_MODIFY",
                    "FILE_DELETE",
                    "FILE_RENAME",
                    "FOLDER_CREATE",
                    "FOLDER_DELETE",
                    "USB_CONNECTED",
                    "USB_FILE_TRANSFER",
                    "MTP_TRANSFER_ATTEMPTED",
                }
                if event_id not in rule_event_ids:
                    triggered_rules = []

                if event_id in {
                    "FILE_CREATE",
                    "FILE_MODIFY",
                    "FILE_DELETE",
                    "FILE_RENAME",
                    "FOLDER_CREATE",
                    "FOLDER_DELETE",
                } and not triggered_rules:
                    return

                if event_id == "FILE_MODIFY":
                    now = time.time()
                    with lock:
                        if now - self.last_file_modification_rule_time < 60:
                            triggered_rules = [
                                rule for rule in triggered_rules
                                if rule.get("rule_id") != 5
                            ]
                        elif any(
                            rule.get("rule_id") == 5
                            for rule in triggered_rules
                        ):
                            self.last_file_modification_rule_time = now

                now = time.time()
                with lock:
                    last_new_rule_times = getattr(self, "last_new_rule_times", {})
                    filtered_rules = []
                    for rule in triggered_rules:
                        rule_id = rule.get("rule_id")
                        if rule_id is not None and rule_id >= 26:
                            if now - last_new_rule_times.get(rule_id, 0) < 60:
                                continue
                            last_new_rule_times[rule_id] = now
                        filtered_rules.append(rule)
                    self.last_new_rule_times = last_new_rule_times
                    triggered_rules = filtered_rules

                if event_id in {
                    "FILE_CREATE",
                    "FILE_MODIFY",
                    "FILE_DELETE",
                    "FILE_RENAME",
                    "FOLDER_CREATE",
                    "FOLDER_DELETE",
                } and not triggered_rules:
                    return

                if not triggered_rules:
                    triggered_rules = [None]

                for rule in triggered_rules:
                    assessment_result = risk_result
                    if rule and rule.get("evidence"):
                        assessment_result = dict(risk_result)
                        assessment_result["evidence"] = [
                            *risk_result.get("evidence", []),
                            rule["evidence"],
                        ]

                    risk_id = record_risk_assessment(
                        assessment_result,
                        notification_triggered=notification_triggered,
                        notification_status=notification_status,
                        alert_message=alert_message,
                        trigger_event_id=event_dict.get("event_id"),
                        trigger_event_source=event_dict.get("source"),
                        trigger_application=event_dict.get("application"),
                        trigger_details=event_dict.get("details"),
                        rule_id=rule.get("rule_id") if rule else None,
                        rule_name=rule.get("rule_name") if rule else None,
                    )
                    if risk_id is not None:
                        try:
                            from reports.session_context import record_assessment

                            record_assessment(
                                event_dict.get("session_id"),
                                risk_id,
                            )
                        except Exception as error:
                            print(
                                "[Forensic Session] Risk assessment association "
                                f"failed: {error}"
                            )
            
            except Exception as error:
                print(f"[Risk Audit DB] Recording failed: {error}")
        
        except Exception as error:
            print(f"[Event Risk Handler] Notification/recording failed: {error}")


# ============================================================================
# GLOBAL HANDLER INSTANCE
# ============================================================================

_handler = EventRiskHandler(debounce_seconds=2)


def assess_event(event_dict):
    """
    Assess risk for a monitoring event.
    
    This is the main entry point for event-driven risk assessment.
    
    Args:
        event_dict: Dictionary with event data
        
    Returns:
        Risk assessment result or None
    """
    return _handler.handle_event(event_dict)


def reset_deduplication():
    """
    Reset the deduplication state (for testing).
    """
    with _handler.lock:
        _handler.last_assessment_type = None
        _handler.last_assessment_time = 0
