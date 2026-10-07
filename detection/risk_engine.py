# detection/risk_engine.py

import sqlite3
import ntpath
from datetime import datetime, timedelta
from pathlib import Path

from detection.rule_registry import get_rule


# ============================================================
# CONFIGURATION
# ============================================================

DB_PATH = Path("database/forensic.db")

# Only recent activity is considered.
WINDOW_MINUTES = 10

# Time after a FILE_COPY event in which an MTP/phone
# Explorer window can be considered related to that transfer.
MTP_CORRELATION_SECONDS = 120

LARGE_TRANSFER_THRESHOLD_BYTES = 100 * 1024 * 1024
BULK_FILE_COUNT_THRESHOLD = 3
MULTIPLE_LARGE_FILES_THRESHOLD = 2

MASS_FILE_MODIFICATION_THRESHOLD = 5
MASS_FILE_MODIFICATION_WINDOW_MINUTES = 1
MASS_FILE_OPERATION_THRESHOLD = 5
MASS_FILE_OPERATION_WINDOW_MINUTES = 1
AFTER_HOURS_START = 22
AFTER_HOURS_END = 6
FILE_ACTIVITY_BURST_THRESHOLD = 5
FILE_ACTIVITY_BURST_WINDOW_MINUTES = 1
UNUSUAL_ACTIVITY_SPIKE_THRESHOLD = 10
UNUSUAL_ACTIVITY_SPIKE_WINDOW_MINUTES = 1
CORRELATION_WINDOW_MINUTES = 10
SUSPICIOUS_ENCRYPTED_EXTENSIONS = {
    ".encrypted",
    ".locked",
    ".crypt",
    ".crypto",
    ".enc",
}
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
}
CONFIGURATION_EXTENSIONS = {
    ".ini",
    ".conf",
    ".cfg",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".config",
    ".toml",
    ".properties",
}
BACKUP_EXTENSIONS = {
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".bkp",
}
SYSTEM_PATH_PREFIXES = (
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
)

SENSITIVE_PATH_MARKERS = {
    "credential",
    "credentials",
    "password",
    "passwords",
    "secret",
    "secrets",
    "private",
    "financial",
    "finance",
    "payroll",
    "tax",
    "identity",
    "personal",
}
SENSITIVE_FILE_EXTENSIONS = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
}

MAX_SCORE = 100


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SIZE FORMATTER
# ============================================================

def format_size(size):

    if size is None:
        return "0 B"

    size = float(size)

    if size < 1024:
        return f"{int(size)} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"

    return f"{size / (1024 * 1024 * 1024):.2f} GB"


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(timestamp):

    try:
        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (ValueError, TypeError):

        return None


def _parse_copy_details(details):
    parsed = {}

    for part in str(details or "").split("|"):
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()

    try:
        file_count = int(parsed.get("FileCount", "0"))
    except (TypeError, ValueError):
        file_count = 0

    try:
        total_size = int(parsed.get("TotalSize", "0").split("bytes", 1)[0].strip())
    except (TypeError, ValueError):
        total_size = 0

    file_sizes = []
    for value in parsed.get("FileSizes", "").split(","):
        try:
            file_sizes.append(int(value.strip()))
        except (TypeError, ValueError):
            continue

    return file_count, total_size, file_sizes


def _parse_detail_fields(details):
    fields = {}
    for part in str(details or "").split("|"):
        key, separator, value = part.partition("=")
        if separator and key.strip():
            fields[key.strip()] = value.strip()
    return fields


def _detect_copy_rules(events, trigger_event):
    if not isinstance(trigger_event, dict):
        return []

    if str(trigger_event.get("event_id", "")).upper() != "FILE_COPY":
        return []

    trigger_details = trigger_event.get("details", "")
    trigger_count, trigger_size, trigger_file_sizes = _parse_copy_details(trigger_details)
    trigger_timestamp = trigger_event.get("timestamp")
    trigger_source = trigger_event.get("source")

    window_file_count = 0
    window_large_file_count = 0
    skipped_trigger_row = False

    for row in events:
        _, timestamp, source, event_id, _, _, details = row
        if str(event_id or "").upper() != "FILE_COPY":
            continue

        if (
            not skipped_trigger_row
            and timestamp == trigger_timestamp
            and source == trigger_source
            and details == trigger_details
        ):
            skipped_trigger_row = True
            continue

        file_count, _, file_sizes = _parse_copy_details(details)
        window_file_count += file_count
        window_large_file_count += sum(
            size >= LARGE_TRANSFER_THRESHOLD_BYTES
            for size in file_sizes
        )

    window_file_count += trigger_count
    window_large_file_count += sum(
        size >= LARGE_TRANSFER_THRESHOLD_BYTES
        for size in trigger_file_sizes
    )

    matches = []

    if trigger_size >= LARGE_TRANSFER_THRESHOLD_BYTES:
        matches.append(1)

    if window_large_file_count >= MULTIPLE_LARGE_FILES_THRESHOLD:
        matches.append(2)

    if window_file_count >= BULK_FILE_COUNT_THRESHOLD:
        matches.append(3)

    return [
        {"rule_id": rule_id, "rule_name": get_rule(rule_id).rule_name}
        for rule_id in matches
    ]


def _detect_mass_file_modification(events, trigger_event):
    if not isinstance(trigger_event, dict):
        return []

    if str(trigger_event.get("event_id", "")).upper() != "FILE_MODIFY":
        return []

    trigger_time = parse_timestamp(trigger_event.get("timestamp"))
    if trigger_time is None:
        return []

    modified_paths = set()
    window = timedelta(minutes=MASS_FILE_MODIFICATION_WINDOW_MINUTES)

    for row in events:
        _, timestamp, source, event_id, _, application, _ = row

        if (
            str(source or "").casefold() != "file monitor"
            or str(event_id or "").upper() != "FILE_MODIFY"
            or not application
            or _is_internal_database_path(application)
        ):
            continue

        event_time = parse_timestamp(timestamp)
        if event_time is None:
            continue

        age = trigger_time - event_time
        if timedelta(0) <= age <= window:
            modified_paths.add(str(application).strip().casefold())

    if len(modified_paths) < MASS_FILE_MODIFICATION_THRESHOLD:
        return []

    rule = get_rule(5)
    return [{
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "evidence": (
            f"{len(modified_paths)} distinct files modified within "
            f"{MASS_FILE_MODIFICATION_WINDOW_MINUTES} minute."
        ),
    }]


def _normalize_windows_path(path):
    if not path:
        return ""
    return ntpath.normcase(ntpath.normpath(str(path).strip().strip('"')))


def _event_window(events, trigger_event, event_ids, minutes):
    trigger_time = parse_timestamp(trigger_event.get("timestamp"))
    if trigger_time is None:
        return []

    allowed_ids = {event_id.upper() for event_id in event_ids}
    cutoff = trigger_time - timedelta(minutes=minutes)
    matches = []

    for row in events:
        _, timestamp, _, event_id, _, application, details = row
        if str(event_id or "").upper() not in allowed_ids:
            continue

        event_time = parse_timestamp(timestamp)
        if event_time is None or not cutoff <= event_time <= trigger_time:
            continue

        matches.append({
            "timestamp": timestamp,
            "event_id": str(event_id).upper(),
            "path": str(application or "").strip(),
            "details": str(details or "").strip(),
        })

    return matches


def _event_old_path(details):
    for part in str(details or "").split("|"):
        key, separator, value = part.partition(":")
        if separator and key.strip().casefold() in {"old path", "source"}:
            return value.strip()
    return ""


def _is_sensitive_path(path):
    normalized = _normalize_windows_path(path)
    if not normalized:
        return False

    components = {
        component.casefold()
        for component in normalized.replace("/", "\\").split("\\")
        if component
    }
    stem = ntpath.splitext(ntpath.basename(normalized))[0].casefold()
    markers = SENSITIVE_PATH_MARKERS | {
        "id_rsa",
        "id_ed25519",
        "credentials",
        "secrets",
    }

    return (
        bool(components & markers)
        or any(marker in stem for marker in markers)
        or ntpath.splitext(normalized)[1].casefold() in SENSITIVE_FILE_EXTENSIONS
    )


def _burst_rule(events, trigger_event, event_id, rule_id, required_paths):
    window_events = _event_window(
        events,
        trigger_event,
        {event_id},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    matching_paths = []

    for event in window_events:
        if event["path"]:
            normalized_path = _normalize_windows_path(event["path"])
            if normalized_path:
                matching_paths.append((normalized_path, event["path"]))

    distinct_paths = {}
    for normalized_path, original_path in matching_paths:
        distinct_paths.setdefault(normalized_path, original_path)

    if len(distinct_paths) < required_paths:
        return []

    rule = get_rule(rule_id)
    paths = " | ".join(distinct_paths.values())
    return [{
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "evidence": (
            f"{len(distinct_paths)} distinct {event_id} paths observed within "
            f"{MASS_FILE_OPERATION_WINDOW_MINUTES} minute: {paths}"
        ),
    }]


def _detect_mass_file_deletion(events, trigger_event):
    if str(trigger_event.get("event_id", "")).upper() != "FILE_DELETE":
        return []
    return _burst_rule(
        events,
        trigger_event,
        "FILE_DELETE",
        7,
        MASS_FILE_OPERATION_THRESHOLD,
    )


def _detect_mass_file_rename(events, trigger_event):
    if str(trigger_event.get("event_id", "")).upper() != "FILE_RENAME":
        return []

    window_events = _event_window(
        events,
        trigger_event,
        {"FILE_RENAME"},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    renamed_paths = {}
    for event in window_events:
        old_path = _event_old_path(event["details"])
        new_path = event["path"]
        if not old_path or not new_path:
            continue
        if ntpath.dirname(_normalize_windows_path(old_path)) != ntpath.dirname(
            _normalize_windows_path(new_path)
        ):
            continue
        renamed_paths.setdefault(
            _normalize_windows_path(new_path),
            (old_path, new_path),
        )

    if len(renamed_paths) < MASS_FILE_OPERATION_THRESHOLD:
        return []

    rule = get_rule(10)
    evidence_paths = " | ".join(
        f"{old_path} -> {new_path}"
        for old_path, new_path in renamed_paths.values()
    )
    return [{
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "evidence": (
            f"{len(renamed_paths)} same-folder rename events observed within "
            f"{MASS_FILE_OPERATION_WINDOW_MINUTES} minute: {evidence_paths}"
        ),
    }]


def _detect_mass_file_move(events, trigger_event):
    if str(trigger_event.get("event_id", "")).upper() != "FILE_RENAME":
        return []

    window_events = _event_window(
        events,
        trigger_event,
        {"FILE_RENAME"},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    moved_paths = {}
    for event in window_events:
        old_path = _event_old_path(event["details"])
        new_path = event["path"]
        if not old_path or not new_path:
            continue
        if ntpath.dirname(_normalize_windows_path(old_path)) == ntpath.dirname(
            _normalize_windows_path(new_path)
        ):
            continue
        moved_paths.setdefault(
            _normalize_windows_path(new_path),
            (old_path, new_path),
        )

    if len(moved_paths) < MASS_FILE_OPERATION_THRESHOLD:
        return []

    rule = get_rule(12)
    evidence_paths = " | ".join(
        f"{old_path} -> {new_path}"
        for old_path, new_path in moved_paths.values()
    )
    return [{
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "evidence": (
            f"{len(moved_paths)} cross-folder move events observed within "
            f"{MASS_FILE_OPERATION_WINDOW_MINUTES} minute: {evidence_paths}"
        ),
    }]


def _detect_file_activity_rules(events, trigger_event):
    event_id = str(trigger_event.get("event_id", "")).upper()
    path = trigger_event.get("application", "")
    details = trigger_event.get("details", "")
    rules = []

    if event_id == "FILE_MODIFY" and _is_sensitive_path(path):
        rule = get_rule(6)
        rules.append({
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "evidence": f"Sensitive-path file modification observed: {path}",
        })

    if event_id == "FILE_DELETE" and _is_sensitive_path(path):
        rule = get_rule(8)
        rules.append({
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "evidence": f"Sensitive-path file deletion observed: {path}",
        })

    if event_id == "FILE_RENAME":
        old_path = _event_old_path(details)
        old_extension = ntpath.splitext(old_path)[1].casefold()
        new_extension = ntpath.splitext(str(path))[1].casefold()
        if old_path and old_extension != new_extension:
            rule = get_rule(11)
            rules.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.rule_name,
                "evidence": (
                    f"File extension changed from {old_extension or '[none]'} "
                    f"to {new_extension or '[none]'}: {old_path} -> {path}"
                ),
            })

    if event_id in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
    }:
        timestamp = parse_timestamp(trigger_event.get("timestamp"))
        if timestamp and (
            timestamp.hour >= AFTER_HOURS_START
            or timestamp.hour < AFTER_HOURS_END
        ):
            rule = get_rule(16)
            rules.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.rule_name,
                "evidence": (
                    f"{event_id} observed at local time "
                    f"{timestamp.strftime('%H:%M:%S')}: {path or details}"
                ),
            })

    if (
        event_id == "USB_FILE_TRANSFER"
        and str(trigger_event.get("source", "")).casefold()
        == "file transfer monitor"
    ):
        parsed = _parse_detail_fields(details)
        if parsed.get("Status", "").casefold() == "success":
            for rule_id, evidence_text in (
                (17, "Successful file transfer observed on monitored removable storage."),
                (18, "Successful file transfer observed on an external/removable drive."),
            ):
                rule = get_rule(rule_id)
                rules.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "evidence": f"{evidence_text} {details}",
                })

    return rules


def _detect_additional_rules(events, trigger_event):
    """Detect supported file activity; unavailable telemetry is never inferred."""

    if not isinstance(trigger_event, dict):
        return []

    event_id = str(trigger_event.get("event_id", "")).upper()
    if (
        event_id in {
            "FILE_CREATE",
            "FILE_MODIFY",
            "FILE_DELETE",
            "FILE_RENAME",
            "FOLDER_CREATE",
            "FOLDER_DELETE",
        }
        and _is_internal_database_path(trigger_event.get("application"))
    ):
        return []

    if event_id not in {
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_CREATE",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
        "MTP_TRANSFER_ATTEMPTED",
    }:
        return []

    rules = _detect_file_activity_rules(events, trigger_event)
    if event_id == "FILE_DELETE":
        rules.extend(_detect_mass_file_deletion(events, trigger_event))
    elif event_id == "FILE_RENAME":
        rules.extend(_detect_mass_file_rename(events, trigger_event))
        rules.extend(_detect_mass_file_move(events, trigger_event))

    return rules


def _make_rule(rule_id, evidence):
    rule = get_rule(rule_id)
    return {
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "evidence": evidence,
    }


def _is_internal_database_path(path):
    normalized = _normalize_windows_path(path)
    filename = ntpath.basename(normalized)
    return (
        filename in {
            "forensic.db",
            "riskalert.db",
            "forensic.sqlite",
            "riskalert.sqlite",
        }
        or filename.endswith(("-wal", "-shm", "-journal"))
    )


def _file_extension(path):
    return ntpath.splitext(ntpath.basename(str(path or "")))[1].casefold()


def _distinct_event_paths(window_events):
    paths = {}
    for event in window_events:
        path = event["path"]
        normalized = _normalize_windows_path(path)
        if normalized and not _is_internal_database_path(normalized):
            paths.setdefault(normalized, path)
    return paths


def _detect_late_file_rules(events, trigger_event):
    if not isinstance(trigger_event, dict):
        return []

    event_id = str(trigger_event.get("event_id", "")).upper()
    path = str(trigger_event.get("application", "") or "").strip()
    details = str(trigger_event.get("details", "") or "")
    rules = []

    if event_id in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FOLDER_CREATE",
        "FOLDER_DELETE",
    } and _is_internal_database_path(path):
        return []

    if event_id == "FILE_CREATE":
        if "hidden=true" in details.casefold():
            rules.append(_make_rule(
                26,
                f"Windows hidden attribute reported for newly created file: {path}",
            ))

    if event_id == "FILE_MODIFY":
        if _is_internal_database_path(path):
            return []

        extension = _file_extension(path)
        if extension in EXECUTABLE_EXTENSIONS:
            rules.append(_make_rule(
                27,
                f"Executable/script file modification observed: {path}",
            ))
        if extension in CONFIGURATION_EXTENSIONS:
            rules.append(_make_rule(
                28,
                f"Configuration file modification observed: {path}",
            ))

        normalized = _normalize_windows_path(path)
        if any(prefix in normalized for prefix in SYSTEM_PATH_PREFIXES):
            rules.append(_make_rule(
                44,
                f"File modification observed under a Windows/system-owned path: {path}",
            ))

    if event_id == "FILE_DELETE":
        if _is_internal_database_path(path):
            return []
        filename = ntpath.basename(_normalize_windows_path(path))
        stem = ntpath.splitext(filename)[0]
        if (
            _file_extension(path) in BACKUP_EXTENSIONS
            or "backup" in stem
            or "backup" in ntpath.dirname(_normalize_windows_path(path))
        ):
            rules.append(_make_rule(
                29,
                f"Identifiable backup-named file deletion observed: {path}",
            ))

    if event_id == "FILE_DELETE":
        rules.extend(_detect_copy_then_delete(events, trigger_event))

    if event_id == "FILE_RENAME":
        rules.extend(_detect_mass_encryption(events, trigger_event))

    if event_id in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FOLDER_CREATE",
        "FOLDER_DELETE",
    }:
        rules.extend(_detect_file_burst_rules(events, trigger_event))

    if event_id in {"FILE_MODIFY", "FILE_RENAME"}:
        rules.extend(_detect_rapid_rename_and_modify(events, trigger_event))

    if event_id in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
        "MTP_TRANSFER_ATTEMPTED",
    }:
        rules.extend(_detect_security_and_device_correlations(events, trigger_event))

    return rules


def _detect_folder_rules(events, trigger_event):
    if not isinstance(trigger_event, dict):
        return []

    event_id = str(trigger_event.get("event_id", "")).upper()
    if event_id not in {"FOLDER_CREATE", "FOLDER_DELETE"}:
        return []

    window_events = _event_window(
        events,
        trigger_event,
        {event_id},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    paths = _distinct_event_paths(window_events)
    if len(paths) < MASS_FILE_OPERATION_THRESHOLD:
        return []

    rule_id = 46 if event_id == "FOLDER_CREATE" else 45
    return [_make_rule(
        rule_id,
        f"{len(paths)} distinct {event_id} paths within "
        f"{MASS_FILE_OPERATION_WINDOW_MINUTES} minute: "
        + " | ".join(paths.values()),
    )]


def _detect_file_burst_rules(events, trigger_event):
    event_id = str(trigger_event.get("event_id", "")).upper()
    window_events = _event_window(
        events,
        trigger_event,
        {"FILE_CREATE", "FILE_MODIFY", "FILE_DELETE", "FILE_RENAME"},
        FILE_ACTIVITY_BURST_WINDOW_MINUTES,
    )
    window_events = [
        event for event in window_events
        if not _is_internal_database_path(event["path"])
    ]
    rules = []

    if event_id in {"FILE_CREATE", "FILE_DELETE", "FILE_RENAME", "FILE_MODIFY"}:
        if event_id == "FILE_CREATE":
            distinct_paths = _distinct_event_paths(window_events)
            if len(distinct_paths) >= MASS_FILE_OPERATION_THRESHOLD:
                rules.append(_make_rule(
                    47,
                    f"{len(distinct_paths)} distinct files created within "
                    f"{FILE_ACTIVITY_BURST_WINDOW_MINUTES} minute: "
                    + " | ".join(distinct_paths.values()),
                ))
        if (
            len(window_events) >= FILE_ACTIVITY_BURST_THRESHOLD
            and any(event["event_id"] != "FILE_MODIFY" for event in window_events)
        ):
            rules.append(_make_rule(
                48,
                f"{len(window_events)} file events observed within "
                f"{FILE_ACTIVITY_BURST_WINDOW_MINUTES} minute.",
            ))
        if len(window_events) >= UNUSUAL_ACTIVITY_SPIKE_THRESHOLD:
            rules.append(_make_rule(
                40,
                f"{len(window_events)} file events observed within "
                f"{UNUSUAL_ACTIVITY_SPIKE_WINDOW_MINUTES} minute "
                "(spike threshold: 10).",
            ))
    return rules


def _detect_rapid_rename_and_modify(events, trigger_event):
    window_events = _event_window(
        events,
        trigger_event,
        {"FILE_RENAME", "FILE_MODIFY"},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    renames = []
    modifications = set()

    for event in window_events:
        normalized = _normalize_windows_path(event["path"])
        if not normalized or _is_internal_database_path(normalized):
            continue
        if event["event_id"] == "FILE_MODIFY":
            modifications.add(normalized)
        elif _file_extension(event["path"]) in SUSPICIOUS_ENCRYPTED_EXTENSIONS:
            old_path = _event_old_path(event["details"])
            if old_path and _file_extension(old_path) != _file_extension(event["path"]):
                renames.append((normalized, event["path"], old_path))

    matching = [
        (new_path, old_path)
        for normalized, new_path, old_path in renames
        if normalized in modifications
    ]
    distinct = {
        _normalize_windows_path(new_path): (old_path, new_path)
        for new_path, old_path in matching
    }
    if len(distinct) < MASS_FILE_OPERATION_THRESHOLD:
        return []

    evidence = " | ".join(
        f"{old_path} -> {new_path}"
        for old_path, new_path in distinct.values()
    )
    return [_make_rule(
        32,
        (
            f"{len(distinct)} renamed files received a FILE_MODIFY event within "
            f"{MASS_FILE_OPERATION_WINDOW_MINUTES} minute; extension pattern is "
            f"encryption-like but does not prove encryption: {evidence}"
        ),
    )]


def _detect_mass_encryption(events, trigger_event):
    window_events = _event_window(
        events,
        trigger_event,
        {"FILE_RENAME"},
        MASS_FILE_OPERATION_WINDOW_MINUTES,
    )
    encrypted_renames = {}
    for event in window_events:
        new_path = event["path"]
        old_path = _event_old_path(event["details"])
        extension = _file_extension(new_path)
        if (
            old_path
            and extension in SUSPICIOUS_ENCRYPTED_EXTENSIONS
            and _file_extension(old_path) != extension
        ):
            encrypted_renames.setdefault(
                _normalize_windows_path(new_path),
                (old_path, new_path),
            )

    if len(encrypted_renames) < MASS_FILE_OPERATION_THRESHOLD:
        return []

    evidence = " | ".join(
        f"{old_path} -> {new_path}"
        for old_path, new_path in encrypted_renames.values()
    )
    return [_make_rule(
        31,
        (
            f"{len(encrypted_renames)} files renamed to encryption-like "
            f"extensions within {MASS_FILE_OPERATION_WINDOW_MINUTES} minute "
            f"(not proof of encryption): {evidence}"
        ),
    )]


def _detect_copy_then_delete(events, trigger_event):
    deleted_path = _normalize_windows_path(trigger_event.get("application"))
    if not deleted_path or _is_internal_database_path(deleted_path):
        return []

    delete_time = parse_timestamp(trigger_event.get("timestamp"))
    if delete_time is None:
        return []

    for row in events:
        _, timestamp, _, event_id, _, _, details = row
        if str(event_id or "").upper() not in {"USB_FILE_TRANSFER", "FILE_COPY"}:
            continue
        copy_time = parse_timestamp(timestamp)
        if copy_time is None:
            continue
        elapsed = delete_time - copy_time
        if elapsed <= timedelta(0) or elapsed > timedelta(minutes=CORRELATION_WINDOW_MINUTES):
            continue

        if str(event_id).upper() == "FILE_COPY":
            # Clipboard selection alone is not proof that a copy completed.
            continue

        parsed = _parse_detail_fields(details)
        source_path = _normalize_windows_path(parsed.get("Source"))
        if (
            parsed.get("Status", "").casefold() == "success"
            and source_path == deleted_path
        ):
            return [_make_rule(
                33,
                (
                    f"Successful removable transfer at {timestamp} recorded source "
                    f"{source_path}, followed by deletion at "
                    f"{trigger_event.get('timestamp')}: {trigger_event.get('details', '')}"
                ),
            )]

    return []


def _detect_security_and_device_correlations(events, trigger_event):
    event_id = str(trigger_event.get("event_id", "")).upper()
    trigger_time = parse_timestamp(trigger_event.get("timestamp"))
    if trigger_time is None:
        return []

    file_event_ids = {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
    }
    current_path = str(trigger_event.get("application", "") or "")
    current_details = str(trigger_event.get("details", "") or "")
    rules = []

    if event_id in file_event_ids:
        security_events = []
        device_events = []
        for row in events:
            _, timestamp, source, row_event_id, _, application, details = row
            row_time = parse_timestamp(timestamp)
            if row_time is None:
                continue
            if abs(trigger_time - row_time) > timedelta(minutes=CORRELATION_WINDOW_MINUTES):
                continue
            row_id = str(row_event_id or "").upper()
            if row_id == "4672" and str(source or "").casefold() == "security log":
                security_events.append((row_id, timestamp, details))
            if row_id == "4625" and str(source or "").casefold() == "security log":
                security_events.append((row_id, timestamp, details))
            if row_id == "USB_CONNECTED" and str(source or "").casefold() == "usb monitor":
                device_events.append((timestamp, details))
        privileged = [
            (timestamp, details)
            for row_id, timestamp, details in security_events
            if row_id == "4672"
        ]
        failed_logins = [
            (timestamp, details)
            for row_id, timestamp, details in security_events
            if row_id == "4625"
            and parse_timestamp(timestamp) <= trigger_time
        ]

        if privileged:
            timestamp, details = privileged[-1]
            rules.append(_make_rule(
                35,
                (
                    f"Security Log privileged-logon event 4672 at {timestamp} "
                    f"correlated with {event_id} {current_path}: {details}"
                ),
            ))
        if failed_logins:
            timestamp, details = failed_logins[-1]
            rules.append(_make_rule(
                39,
                (
                    f"Security Log failed-login event 4625 at {timestamp} "
                    f"preceded {event_id} {current_path}: {details}"
                ),
            ))

        for timestamp, device_details in device_events:
            device_time = parse_timestamp(timestamp)
            if device_time is None or device_time > trigger_time:
                continue
            if trigger_time - device_time <= timedelta(minutes=CORRELATION_WINDOW_MINUTES):
                rules.append(_make_rule(
                    36,
                    (
                        f"New USB device event at {timestamp} temporally correlated "
                        f"with {event_id} {current_path or current_details}; "
                        f"device telemetry: {device_details}"
                    ),
                ))
                break

    return rules


def _base_rules_for_event_window(events, trigger_event):
    event_id = str(trigger_event.get("event_id", "")).upper()
    if event_id not in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
        "MTP_TRANSFER_ATTEMPTED",
        "FOLDER_CREATE",
        "FOLDER_DELETE",
    }:
        return []

    return (
        _detect_copy_rules(events, trigger_event)
        + _detect_mass_file_modification(events, trigger_event)
        + _detect_additional_rules(events, trigger_event)
        + _detect_late_file_rules(events, trigger_event)
        + _detect_folder_rules(events, trigger_event)
    )


def _detect_composite_rule_events(events, trigger_event):
    if not isinstance(trigger_event, dict):
        return []

    if str(trigger_event.get("event_id", "")).upper() not in {
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "FILE_RENAME",
        "FILE_COPY",
        "USB_FILE_TRANSFER",
        "MTP_TRANSFER_ATTEMPTED",
        "FOLDER_CREATE",
        "FOLDER_DELETE",
    }:
        return []

    trigger_time = parse_timestamp(trigger_event.get("timestamp"))
    if trigger_time is None:
        return []

    detected = {}
    evidence_by_rule = {}
    cutoff = trigger_time - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    window_rows = [
        row for row in events
        if (event_time := parse_timestamp(row[1])) is not None
        and cutoff <= event_time <= trigger_time
    ]

    contributing_events = set()
    for row in window_rows:
        _, timestamp, source, event_id, action, application, details = row
        event = {
            "timestamp": timestamp,
            "source": source,
            "event_id": str(event_id or "").upper(),
            "action": action,
            "application": application,
            "details": details,
        }
        row_events = [
            candidate for candidate in window_rows
            if (
                parse_timestamp(candidate[1]) is not None
                and parse_timestamp(candidate[1]) <= parse_timestamp(timestamp)
                and parse_timestamp(candidate[1])
                >= parse_timestamp(timestamp) - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
            )
        ]
        for rule in _base_rules_for_event_window(row_events, event):
            rule_id = rule["rule_id"]
            if rule_id in {41, 50}:
                continue
            detected.setdefault(rule_id, [])
            detected[rule_id].append((timestamp, event["event_id"], application, rule.get("evidence", "")))
            evidence_by_rule.setdefault(rule_id, rule.get("evidence", ""))
            contributing_events.add((
                timestamp,
                event["event_id"],
                _normalize_windows_path(application),
            ))

    if len(detected) < 2 or len(contributing_events) < 2:
        return []

    support = []
    for rule_id in sorted(detected):
        event_timestamp, event_id, application, evidence = detected[rule_id][-1]
        support.append(
            f"Rule {rule_id} at {event_timestamp} ({event_id}, {application}): "
            f"{evidence or evidence_by_rule[rule_id]}"
        )
    evidence = " | ".join(support)
    rules = [_make_rule(
        41,
        f"{len(detected)} distinct detected rule types within "
        f"{CORRELATION_WINDOW_MINUTES} minutes: {evidence}",
    )]
    if len(detected) >= 3:
        rules.append(_make_rule(
            50,
            f"Combined {len(detected)} distinct detected rule types within "
            f"{CORRELATION_WINDOW_MINUTES} minutes: {evidence}",
        ))
    return rules


# ============================================================
# GET RECENT EVENTS
# ============================================================

def get_recent_events():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cutoff = datetime.now() - timedelta(
        minutes=WINDOW_MINUTES
    )

    rows = cursor.execute(
        """
        SELECT
            id,
            timestamp,
            source,
            event_id,
            action,
            application,
            details
        FROM events
        WHERE timestamp >= ?
        ORDER BY id ASC
        """,
        (
            cutoff.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        )
    ).fetchall()

    conn.close()

    return rows


# ============================================================
# MTP / PHONE WINDOW DETECTION
#
# IMPORTANT:
# This does NOT claim that a paste was definitely successful.
#
# Windows MTP devices do not behave like normal filesystem
# drives, so watchdog cannot reliably generate FILE_CREATE
# events for the phone.
#
# We therefore detect:
#
# USB connected
#       +
# FILE_COPY
#       +
# Phone / Internal Storage / MTP Explorer window
#
# and report:
#
# MTP DESTINATION SUSPECTED
#
# rather than falsely claiming:
#
# FILE PASTED
# ============================================================

def is_mtp_window(application):

    if not application:
        return False

    text = str(application).lower()

    mtp_keywords = [

        # Generic phone/storage terms
        "internal shared storage",
        "internal storage",
        "phone storage",
        "phone",
        "mobile device",
        "portable device",
        "mtp",

        # Windows Explorer indicators
        "file explorer",

        # Common Android storage names
        "dcim",
        "pictures",
        "documents",
        "download",
        "project"
    ]

    return any(
        keyword in text
        for keyword in mtp_keywords
    )


# ============================================================
# ANALYZE FORENSIC ACTIVITY
# ============================================================

def assess_risk(trigger_event=None):

    events = get_recent_events()


    # ========================================================
    # COUNTERS
    # ========================================================

    usb_connections = 0
    usb_removals = 0

    files_copied = 0
    total_copy_size = 0

    security_events = 0

    file_deletions = 0
    file_creations = 0
    file_modifications = 0

    application_events = 0


    # ========================================================
    # FLAGS
    # ========================================================

    bulk_transfer = False
    large_transfer = False

    deletion_activity = False
    security_anomaly = False

    mtp_window_detected = False
    mtp_transfer_suspected = False


    # ========================================================
    # EVENT STORAGE
    # ========================================================

    copy_events = []
    mtp_windows = []


    # ========================================================
    # EVIDENCE
    # ========================================================

    evidence = []


    # ========================================================
    # PROCESS EVENTS
    # ========================================================

    for row in events:

        (
            event_id_db,
            timestamp,
            source,
            event_id,
            action,
            application,
            details
        ) = row


        event_id = str(
            event_id or ""
        ).upper()

        source_text = str(
            source or ""
        ).lower()

        application_text = str(
            application or ""
        )

        details_text = str(
            details or ""
        )


        event_time = parse_timestamp(
            timestamp
        )


        # ====================================================
        # USB CONNECTED
        # ====================================================

        if event_id == "USB_CONNECTED":

            usb_connections += 1


        # ====================================================
        # USB REMOVED
        # ====================================================

        elif event_id == "USB_REMOVED":

            usb_removals += 1


        # ====================================================
        # FILE COPY
        # ====================================================

        elif event_id == "FILE_COPY":

            count = 0
            size = 0


            # ------------------------------------------------
            # File count
            # ------------------------------------------------

            count, size, _ = _parse_copy_details(details_text)


            files_copied += count

            total_copy_size += size


            if event_time:

                copy_events.append(
                    event_time
                )


        # ====================================================
        # FILE DELETE
        # ====================================================

        elif event_id == "FILE_DELETE":

            file_deletions += 1

            deletion_activity = True


        # ====================================================
        # FILE CREATE
        # ====================================================

        elif event_id == "FILE_CREATE":

            file_creations += 1


        # ====================================================
        # FILE MODIFY
        # ====================================================

        elif event_id == "FILE_MODIFY":

            file_modifications += 1


        # ====================================================
        # PROCESS / APPLICATION
        # ====================================================

        elif event_id in (
            "4688",
            "4689"
        ):

            application_events += 1


        # ====================================================
        # ACTIVE WINDOW / MTP WINDOW
        # ====================================================

        if event_id == "WINDOW_CHANGE":

            if is_mtp_window(
                application_text
            ):

                mtp_window_detected = True

                if event_time:

                    mtp_windows.append(
                        event_time
                    )


        # ====================================================
        # SECURITY EVENTS
        # ====================================================

        if (
            "security" in source_text
            or event_id in (
                "4625",
                "4776"
            )
        ):

            security_events += 1

            security_anomaly = True


    # ========================================================
    # DERIVED INDICATORS
    # ========================================================

    if files_copied >= BULK_FILE_COUNT_THRESHOLD:

        bulk_transfer = True


    if total_copy_size >= LARGE_TRANSFER_THRESHOLD_BYTES:

        large_transfer = True


    # ========================================================
    # MTP TRANSFER CORRELATION
    #
    # We only call it "suspected".
    #
    # We NEVER claim the paste succeeded because Windows
    # does not expose MTP copy/paste as a normal filesystem
    # event.
    # ========================================================

    if (
        usb_connections > 0
        and files_copied > 0
        and mtp_windows
        and copy_events
    ):

        for copy_time in copy_events:

            for window_time in mtp_windows:

                difference = (
                    window_time - copy_time
                ).total_seconds()

                if (
                    0 <= difference
                    <= MTP_CORRELATION_SECONDS
                ):

                    mtp_transfer_suspected = True

                    break

            if mtp_transfer_suspected:

                break


    # ========================================================
    # SCORE
    # ========================================================

    score = 0


    # ========================================================
    # USB ACTIVITY
    # ========================================================

    if usb_connections > 0:

        score += 5

        evidence.append(
            "External USB device activity detected."
        )


    # ========================================================
    # FILE COPY ACTIVITY
    # ========================================================

    if files_copied > 0:

        if files_copied <= 2:

            score += 5

            evidence.append(
                f"{files_copied} file(s) copied."
            )

        elif files_copied < 10:

            score += 10

            evidence.append(
                f"Bulk file-copy activity detected "
                f"({files_copied} files)."
            )

        else:

            score += 20

            evidence.append(
                f"High-volume file-copy activity detected "
                f"({files_copied} files)."
            )


    # ========================================================
    # TRANSFER SIZE
    # ========================================================

    if total_copy_size >= LARGE_TRANSFER_THRESHOLD_BYTES:

        score += 20

        evidence.append(
            "Large data transfer volume detected "
            f"({format_size(total_copy_size)})."
        )

    elif total_copy_size >= (
        10 * 1024 * 1024
    ):

        score += 10

        evidence.append(
            "Moderate data transfer volume detected "
            f"({format_size(total_copy_size)})."
        )

    elif total_copy_size > 0:

        evidence.append(
            f"Transfer volume: "
            f"{format_size(total_copy_size)}."
        )


    # ========================================================
    # USB + FILE COPY
    # ========================================================

    if (
        usb_connections > 0
        and files_copied > 0
    ):

        score += 10

        evidence.append(
            "USB activity correlated with "
            "file-copy behavior."
        )


    # ========================================================
    # USB + BULK TRANSFER
    # ========================================================

    if (
        usb_connections > 0
        and bulk_transfer
    ):

        score += 10

        evidence.append(
            "Bulk transfer occurred while "
            "an external USB device was active."
        )


    # ========================================================
    # MTP / PHONE TRANSFER
    #
    # IMPORTANT:
    # This adds only a SMALL amount of risk because a phone
    # transfer by itself is not malicious.
    # ========================================================

    if mtp_transfer_suspected:

        score += 5

        evidence.append(
            "MTP/phone destination activity correlated "
            "with the file-copy event."
        )

        evidence.append(
            "Destination is suspected but cannot be "
            "verified through the Windows MTP interface."
        )


    elif (
        mtp_window_detected
        and usb_connections > 0
    ):

        evidence.append(
            "Phone/MTP Explorer activity detected."
        )


    # ========================================================
    # SECURITY ANOMALY + TRANSFER
    # ========================================================

    if (
        security_anomaly
        and files_copied > 0
    ):

        score += 20

        evidence.append(
            "Security anomaly correlated with "
            "file-transfer activity."
        )

    elif security_anomaly:

        score += 10

        evidence.append(
            "Security-related anomaly detected."
        )


    # ========================================================
    # DELETION + TRANSFER
    # ========================================================

    if (
        deletion_activity
        and files_copied > 0
    ):

        score += 10

        evidence.append(
            "File deletion occurred during "
            "file-transfer activity."
        )


    # ========================================================
    # LARGE TRANSFER + USB
    # ========================================================

    if (
        large_transfer
        and usb_connections > 0
    ):

        score += 10

        evidence.append(
            "Large transfer correlated with "
            "external USB activity."
        )


    # ========================================================
    # LIMIT SCORE
    # ========================================================

    score = min(
        score,
        MAX_SCORE
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    risk = get_risk_level(
        score
    )


    # ========================================================
    # TRANSFER STATUS
    # ========================================================

    if files_copied == 0:

        transfer_status = (
            "NO FILE TRANSFER DETECTED"
        )

    elif mtp_transfer_suspected:

        transfer_status = (
            "MTP DESTINATION SUSPECTED / "
            "DESTINATION UNVERIFIED"
        )

    elif usb_connections > 0:

        transfer_status = (
            "USB TRANSFER ACTIVITY DETECTED"
        )

    else:

        transfer_status = (
            "COPY DETECTED / "
            "DESTINATION UNVERIFIED"
        )


    # ========================================================
    # NO EVIDENCE
    # ========================================================

    if not evidence:

        evidence.append(
            "No significant forensic indicators."
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "risk":
            risk,

        "score":
            score,

        "usb_connections":
            usb_connections,

        "usb_removals":
            usb_removals,

        "files_copied":
            files_copied,

        "total_copy_size":
            total_copy_size,

        "total_copy_size_display":
            format_size(
                total_copy_size
            ),

        "security_events":
            security_events,

        "file_deletions":
            file_deletions,

        "file_creations":
            file_creations,

        "file_modifications":
            file_modifications,

        "application_events":
            application_events,

        "mtp_window_detected":
            mtp_window_detected,

        "mtp_transfer_suspected":
            mtp_transfer_suspected,

        "transfer_status":
            transfer_status,

        "evidence":
            evidence,

        "window_minutes":
            WINDOW_MINUTES,

        "triggered_rules":
            (
                _detect_copy_rules(events, trigger_event)
                + _detect_mass_file_modification(events, trigger_event)
                + _detect_additional_rules(events, trigger_event)
                + _detect_late_file_rules(events, trigger_event)
                + _detect_folder_rules(events, trigger_event)
                + _detect_composite_rule_events(events, trigger_event)
            )
    }


    return result


# ============================================================
# TERMINAL DISPLAY
# ============================================================

def print_assessment():

    result = assess_risk()


    print()
    print("=" * 70)

    print(
        "FORENSICGUARD - FORENSIC RISK ASSESSMENT"
    )

    print("=" * 70)


    print(
        f"\nRisk Level       : "
        f"{result['risk']}"
    )

    print(
        f"Risk Score       : "
        f"{result['score']}/100"
    )

    print(
        f"USB Connections  : "
        f"{result['usb_connections']}"
    )

    print(
        f"Files Copied     : "
        f"{result['files_copied']}"
    )

    print(
        f"Total Copy Size  : "
        f"{result['total_copy_size_display']}"
    )

    print(
        f"Security Events  : "
        f"{result['security_events']}"
    )

    print(
        f"MTP Activity     : "
        f"{'YES' if result['mtp_window_detected'] else 'NO'}"
    )

    print(
        f"MTP Transfer     : "
        f"{'SUSPECTED' if result['mtp_transfer_suspected'] else 'NOT VERIFIED'}"
    )

    print(
        f"Transfer Status  : "
        f"{result['transfer_status']}"
    )


    print(
        "\nEvidence:"
    )


    for item in result["evidence"]:

        print(
            f"  • {item}"
        )


    print(
        "=" * 70
    )


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print_assessment()