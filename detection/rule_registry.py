"""Central registry for the official ForensicGuard 50 risk alert rules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskRule:
    """Official rule metadata used for database identification and auditing."""

    rule_id: int
    rule_name: str
    short_description: str
    status: str = "PENDING"
    required_telemetry: str = ""


OFFICIAL_50_RULES = (
    RiskRule(1, "Large File Copy", "A single large file copy exceeds normal transfer thresholds.", "PENDING", "FILE_COPY + TotalSize"),
    RiskRule(2, "Multiple Large Files Copy", "Several large files are copied in a short interval.", "PENDING", "FILE_COPY burst + TotalSize"),
    RiskRule(3, "Bulk File Copy", "A large number of files are copied as a single transfer event.", "PENDING", "FILE_COPY count + TotalSize"),
    RiskRule(4, "File Paste from External Source", "A file appears to be pasted from an external device or non-local source.", "PENDING", "clipboard + USB / MTP / external-source correlation"),
    RiskRule(5, "Mass File Modification", "A burst of file modifications suggests broader tampering or ransomware behavior.", "PENDING", "FILE_MODIFY burst"),
    RiskRule(6, "Sensitive File Modification", "Sensitive files or directories are modified.", "PARTIAL", "FILE_MODIFY + sensitive files / paths"),
    RiskRule(7, "Mass File Deletion", "Many files are deleted in a short period.", "PARTIAL", "FILE_DELETE burst"),
    RiskRule(8, "Sensitive File Deletion", "Sensitive data files are deleted.", "PARTIAL", "FILE_DELETE + sensitive file/path detection"),
    RiskRule(9, "Permanent File Deletion", "Files are deleted in a way that appears destructive or irrecoverable.", "PARTIAL", "FILE_DELETE + secure-delete / recycle-state context"),
    RiskRule(10, "Mass File Rename", "Many files are renamed quickly, often during staging or mass tampering.", "PARTIAL", "FILE_RENAME burst"),
    RiskRule(11, "File Extension Change", "File extension changes suggest rename, disguise, or encryption staging.", "FULL", "FILE_RENAME / move + extension diff"),
    RiskRule(12, "Mass File Move", "Files are moved rapidly between folders or drives.", "PARTIAL", "FILE_RENAME / move burst"),
    RiskRule(13, "Sensitive Folder Access", "A protected or sensitive folder is accessed unusually.", "PARTIAL", "folder access + protected-path telemetry"),
    RiskRule(14, "Mass File Access", "High-volume file access indicates broad enumeration or staging.", "PARTIAL", "file access events + burst count"),
    RiskRule(15, "Unusual File Access", "File access is inconsistent with user behavior or the usual workload.", "PARTIAL", "file access anomaly patterns"),
    RiskRule(16, "After-Hours File Activity", "File activity occurs outside normal working hours.", "PARTIAL", "timestamped file events + hour-of-day context"),
    RiskRule(17, "USB File Transfer", "Files are copied or moved to or from a USB device.", "FULL", "USB_FILE_TRANSFER + successful removable-drive write"),
    RiskRule(18, "External Drive Transfer", "Files move to or from an external drive or removable storage.", "FULL", "successful file event on monitored removable storage"),
    RiskRule(19, "Network File Transfer", "Files are transferred over network or shared drive paths.", "PARTIAL", "network share / SMB / mapped drive telemetry"),
    RiskRule(20, "Cloud Upload", "Data is uploaded to cloud storage or sync destinations.", "PARTIAL", "browser / sync-client / cloud upload telemetry"),
    RiskRule(21, "External Email Transfer", "Files are sent via email or external communication channels.", "PARTIAL", "email attachment / outbound-mail telemetry"),
    RiskRule(22, "Large Data Upload", "A large upload volume indicates potential exfiltration.", "PARTIAL", "upload event + TotalSize"),
    RiskRule(23, "Mass Download", "A rapid burst of downloads indicates unusual collection or caching.", "PARTIAL", "download folder + browser / file events"),
    RiskRule(24, "Permission Change", "File or directory permissions change unexpectedly.", "PARTIAL", "ACL / security descriptor changes"),
    RiskRule(25, "Ownership Change", "File ownership changes unexpectedly.", "PARTIAL", "ownership / file security metadata changes"),
    RiskRule(26, "Hidden File Creation", "Hidden files are created during suspicious activity.", "FULL", "FILE_CREATE + Windows hidden attribute"),
    RiskRule(27, "Executable File Modification", "Executable or script files are modified unexpectedly.", "FULL", "FILE_MODIFY + executable extension detection"),
    RiskRule(28, "Configuration File Modification", "System or software configuration files are changed.", "FULL", "FILE_MODIFY + configuration extension detection"),
    RiskRule(29, "Backup File Deletion", "Backup files are deleted, reducing recovery options.", "PARTIAL", "FILE_DELETE + identifiable backup naming/extensions"),
    RiskRule(30, "Snapshot/Restore Point Deletion", "Restore points or snapshots are deleted.", "PARTIAL", "VSS/restore-point deletion telemetry unavailable; no attribution"),
    RiskRule(31, "Mass Encryption", "Large numbers of files are encrypted or converted to suspicious formats.", "PARTIAL", "FILE_RENAME burst to encryption-like extensions; encryption unverified"),
    RiskRule(32, "Rapid Rename + Encryption", "Files are rapidly renamed and encrypted in the same activity burst.", "PARTIAL", "FILE_RENAME + FILE_MODIFY burst + encryption-like extensions"),
    RiskRule(33, "Copy + Delete Original", "Copies are made and originals are removed shortly afterward.", "PARTIAL", "successful USB_FILE_TRANSFER + subsequent FILE_DELETE of exact source path"),
    RiskRule(34, "Access + External Transfer", "Sensitive file access coincides with an external transfer.", "PARTIAL", "file-access telemetry unavailable; no attribution"),
    RiskRule(35, "Privilege Change + File Activity", "Privilege or elevation changes align with suspicious file activity.", "PARTIAL", "Security Log 4672 + nearby file event; user identity linkage unavailable"),
    RiskRule(36, "New Device Activity", "A newly connected device shows unusual transfer or access behavior.", "PARTIAL", "USB_CONNECTED + temporally correlated file activity"),
    RiskRule(37, "Unusual Location Activity", "File or access activity is associated with an unusual or untrusted location.", "PARTIAL", "trusted-location baseline unavailable; no attribution"),
    RiskRule(38, "Dormant Account Activity", "An inactive or dormant account suddenly performs activity.", "PARTIAL", "account dormancy baseline unavailable; no attribution"),
    RiskRule(39, "Failed Login + File Activity", "Failed login activity is followed by file-system actions.", "PARTIAL", "Security Log 4625 + subsequent file event; user identity linkage unavailable"),
    RiskRule(40, "Unusual Activity Spike", "An abnormal spike in endpoint activity is observed.", "PARTIAL", "10 file events within 1 minute"),
    RiskRule(41, "Multiple Suspicious Operations", "Several suspicious indicators are observed together.", "PARTIAL", "2+ distinct detected rule IDs within 10 minutes"),
    RiskRule(42, "High-Risk Process File Activity", "A high-risk process interacts with sensitive files or creates suspicious patterns.", "PARTIAL", "process identity is not captured on file events; no attribution"),
    RiskRule(43, "Protected File Access", "Files in protected or system-critical paths are accessed.", "PARTIAL", "file-access telemetry unavailable; no attribution"),
    RiskRule(44, "System File Modification", "Core system files are modified or replaced.", "PARTIAL", "FILE_MODIFY + Windows/system path classification; monitor scope excludes most system paths"),
    RiskRule(45, "Mass Folder Deletion", "Many folders are deleted in a single burst.", "PARTIAL", "5 distinct FOLDER_DELETE events within 1 minute in watched paths"),
    RiskRule(46, "Mass Folder Creation", "Many folders are created in a burst.", "PARTIAL", "5 distinct FOLDER_CREATE events within 1 minute in watched paths"),
    RiskRule(47, "Mass File Creation", "Many files are created rapidly during suspicious or bulk activity.", "PARTIAL", "5 distinct FILE_CREATE paths within 1 minute in watched paths"),
    RiskRule(48, "File Activity Burst", "A short burst of file-related activity indicates abnormal behavior.", "PARTIAL", "5 FILE_CREATE/MODIFY/DELETE/RENAME events, including a non-FILE_MODIFY event, within 1 minute"),
    RiskRule(49, "Unusual File Type Activity", "Unexpected file types or extensions appear in suspicious activity patterns.", "PARTIAL", "file-type baseline unavailable; no rule attribution"),
    RiskRule(50, "Combined Risk Detection", "Multiple suspicious indicators are combined into one risk determination.", "PARTIAL", "3+ distinct detected rule IDs within 10 minutes"),
)

RULE_LOOKUP = {rule.rule_id: rule for rule in OFFICIAL_50_RULES}
RULE_NAME_LOOKUP = {rule.rule_name: rule for rule in OFFICIAL_50_RULES}


def get_rule(rule_id):
    """Return the official rule definition for the supplied rule id."""

    return RULE_LOOKUP.get(int(rule_id))


def get_rule_name(rule_id):
    """Return the official rule name for the supplied rule id."""

    rule = get_rule(rule_id)
    return rule.rule_name if rule is not None else None


def get_rule_by_name(rule_name):
    """Return the official rule definition for the supplied rule name."""

    if rule_name is None:
        return None

    return RULE_NAME_LOOKUP.get(str(rule_name).strip())


def is_valid_rule_id(rule_id):
    """Return True when the supplied id matches an official rule."""

    return get_rule(rule_id) is not None


__all__ = [
    "RiskRule",
    "OFFICIAL_50_RULES",
    "RULE_LOOKUP",
    "RULE_NAME_LOOKUP",
    "get_rule",
    "get_rule_name",
    "get_rule_by_name",
    "is_valid_rule_id",
]
