//! Detection rules, regex patterns, and behavioral-analysis defaults.

mod patterns;
pub use patterns::*;

pub const ENABLE_BEHAVIORAL_ANALYSIS: bool = true;
pub const BEHAVIOR_WINDOW_MINUTES: i64 = 5;
pub const HIGH_SEVERITY_THRESHOLD: u32 = 10;

pub const SUSPICIOUS_PROCESSES: [&str; 32] = [
    "meterpreter",
    "cobaltstrike",
    "metasploit",
    "netcat",
    "nc",
    "ncat",
    "powershell -e",
    "powershell -enc",
    "powershell -w hidden",
    "powershell -nop",
    "certutil",
    "bitsadmin",
    "wmic",
    "mshta",
    "rundll32",
    "regsvr32",
    "schtasks",
    "psexec",
    "paexec",
    "winexe",
    "at.exe",
    "sc.exe",
    "netsh",
    "ipconfig",
    "nslookup",
    "ping",
    "telnet",
    "whoami",
    "systeminfo",
    "tasklist",
    "net user",
    "net localgroup",
];

pub const CRITICAL_ASSETS: [&str; 21] = [
    "domain-controller",
    "domain controller",
    "active directory",
    "ldap",
    "database-server",
    "database server",
    "mysql",
    "postgresql",
    "oracle",
    "mssql",
    "payment-gateway",
    "payment gateway",
    "pos system",
    "erp-system",
    "erp system",
    "sap",
    "oracle erp",
    "scada-system",
    "scada system",
    "hmi",
    "plc",
];

pub const CORRELATION_RULES: [(&str, &str); 18] = [
    (
        "brute_force",
        r"(?i)(authentication failure|login failed|invalid password|bad password)",
    ),
    (
        "port_scan",
        r"(?i)(scan detected|port scan|reconnaissance|nmap)",
    ),
    (
        "malware_exec",
        r"(?i)(malware|virus|trojan|backdoor|rootkit|ransomware)",
    ),
    (
        "suspicious_login",
        r"(?i)(login outside business hours|unusual login time|after hours access)",
    ),
    (
        "data_exfiltration",
        r"(?i)(large data transfer|exfiltration|data leak|file upload|ftp transfer)",
    ),
    (
        "privilege_escalation",
        r"(?i)(sudo|su |privilege escalation|elevated privileges|admin access)",
    ),
    (
        "config_change",
        r"(?i)(configuration changed|config modified|settings altered)",
    ),
    (
        "critical_service_stop",
        r"(?i)(service stopped|service terminated|critical service down)",
    ),
    (
        "new_service",
        r"(?i)(new service installed|service created|service registered)",
    ),
    (
        "persistence",
        r"(?i)(persistence mechanism|startup item|autostart|registry run key)",
    ),
    (
        "lateral_movement",
        r"(?i)(lateral movement|remote execution|psexec|wmi execution)",
    ),
    (
        "command_and_control",
        r"(?i)(c2|c&c|command and control|beacon|callback)",
    ),
    (
        "policy_violation",
        r"(?i)(policy violation|security policy|compliance violation)",
    ),
    (
        "suspicious_network",
        r"(?i)(suspicious connection|malicious ip|blocked connection)",
    ),
    (
        "crypto_mining",
        r"(?i)(crypto mining|cryptocurrency|bitcoin|monero|mining pool)",
    ),
    (
        "sql_injection_attempt",
        r"(?i)(sql injection|sqli|union\s+select|drop\s+table|insert\s+into)",
    ),
    (
        "network_threat_detected",
        r"(?i)(threat|vulnerability|exploit|attack|intrusion)",
    ),
    (
        "high_risk_protocol",
        r"(?i)\b(telnet|rsh|rlogin|tftp|ftp)\b",
    ),
];

#[allow(dead_code)]
pub const HIGH_RISK_APP_CATEGORIES: [&str; 15] = [
    "peer-to-peer",
    "file-sharing",
    "proxy",
    "anonymizer",
    "tunneling",
    "hacking-tools",
    "malware",
    "command-and-control",
    "cryptocurrency",
    "gaming",
    "social-networking",
    "instant-messaging",
    "remote-access",
    "backup",
    "storage-backup",
];
