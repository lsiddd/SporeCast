// Fields 0–30: identical layout for TRAFFIC, THREAT, and most other PAN-OS log types.
pub(super) const COMMON_HEADERS: &[&str] = &[
    "Log Number",           // 0
    "Receive Time",         // 1
    "Serial Number",        // 2
    "Type",                 // 3
    "Threat/Content Type",  // 4
    "Config Version",       // 5
    "Generated Time",       // 6
    "Source address",       // 7
    "Destination address",  // 8
    "NAT source IP",        // 9
    "NAT destination IP",   // 10
    "Rule Name",            // 11
    "Source User",          // 12
    "Destination User",     // 13
    "Application",          // 14
    "Virtual System",       // 15
    "Source Zone",          // 16
    "Destination Zone",     // 17
    "Inbound Interface",    // 18
    "Outbound Interface",   // 19
    "Log Action",           // 20
    "Time Logged",          // 21
    "Session ID",           // 22
    "Repeat Count",         // 23
    "Source Port",          // 24
    "Destination Port",     // 25
    "NAT Source Port",      // 26
    "NAT Destination Port", // 27
    "Flags",                // 28
    "IP Protocol",          // 29
    "Action",               // 30
];

// Fields 31+ for TRAFFIC logs.
pub(super) const TRAFFIC_EXTRA_HEADERS: &[&str] = &[
    "Bytes",                             // 31
    "Bytes Sent",                        // 32
    "Bytes Received",                    // 33
    "Packets",                           // 34
    "Start Time",                        // 35
    "Elapsed Time in seconds",           // 36
    "Category",                          // 37
    "Padding",                           // 38
    "Sequence Number",                   // 39
    "Action Flags",                      // 40
    "Source Location",                   // 41
    "Destination Location",              // 42
    "Padding-2",                         // 43
    "Packets Sent",                      // 44
    "Packets Received",                  // 45
    "Session End Reason",                // 46
    "Device Group Hierarchy Level 1",    // 47
    "Device Group Hierarchy Level 2",    // 48
    "Device Group Hierarchy Level 3",    // 49
    "Device Group Hierarchy Level 4",    // 50
    "Virtual System Name",               // 51
    "Device Name",                       // 52
    "Action Source",                     // 53
    "Source VM UUID",                    // 54
    "Destination VM UUID",               // 55
    "Tunnel ID/IMSI",                    // 56
    "Monitor Tag/IMEI",                  // 57
    "Parent Session ID",                 // 58
    "Parent Start Time",                 // 59
    "Tunnel Type",                       // 60
    "SCTP Association ID",               // 61
    "SCTP Chunks",                       // 62
    "SCTP Chunks Sent",                  // 63
    "SCTP Chunks Received",              // 64
    "UUID for rule",                     // 65
    "HTTP/2 Connection",                 // 66
    "Application-Level-Link-Changes",    // 67
    "Policy-ID",                         // 68
    "Link-Switches",                     // 69
    "SD-WAN-Cluster",                    // 70
    "SD-WAN-Device-Type",               // 71
    "SD-WAN-Cluster-Type",              // 72
    "SD-WAN-Site",                       // 73
    "Dynamic-User-Group-Name",          // 74
    "X-Forwarded-For-Address",          // 75
    "Source-Device-Category",           // 76
    "Source-Device-Profile",            // 77
    "Source-Device-Model",              // 78
    "Source-Device-Vendor",             // 79
    "Source-Device-OS-Family",          // 80
    "Source-Device-OS-Version",         // 81
    "Source-Hostname",                  // 82
    "Source-MAC-Address",               // 83
    "Destination-Device-Category",      // 84
    "Destination-Device-Profile",       // 85
    "Destination-Device-Model",         // 86
    "Destination-Device-Vendor",        // 87
    "Destination-Device-OS-Family",     // 88
    "Destination-Device-OS-Version",    // 89
    "Destination-Hostname",             // 90
    "Destination-MAC-Address",          // 91
    "Container-ID",                     // 92
    "POD-Namespace",                    // 93
    "POD-Name",                         // 94
    "Source-External-Dynamic-List",     // 95
    "Destination-External-Dynamic-List",// 96
    "Host-ID",                          // 97
    "User-Device-Serial-Number",        // 98
    "Source-Dynamic-Address-Group",     // 99
    "Destination-Dynamic-Address-Group",// 100
    "Session-Owner",                    // 101
    "High-Resolution-Timestamp",        // 102
    "A-Slice-Service-Type",             // 103
    "A-Slice-Differentiator",           // 104
    "Application-Subcategory",          // 105
    "Application-Category",             // 106
    "Application-Technology",           // 107
    "Application-Risk",                 // 108
    "Application-Characteristics",      // 109
    "Application-Container-Name",       // 110
    "Tunneled-Application",             // 111
    "is-SAAS-App",                      // 112
    "Application-Sanctioned-State",     // 113
    "Offloaded",                        // 114
];

// Fields 31+ for THREAT logs (URL/file/spyware/vulnerability/etc.).
pub(super) const THREAT_EXTRA_HEADERS: &[&str] = &[
    "Threat Name",                       // 31
    "Threat ID",                         // 32
    "Category",                          // 33
    "Severity",                          // 34
    "Direction",                         // 35
    "Sequence Number",                   // 36
    "Action Flags",                      // 37
    "Source Location",                   // 38
    "Destination Location",              // 39
    "Padding",                           // 40
    "Content Type",                      // 41
    "PCAP ID",                           // 42
    "File Digest",                       // 43
    "Cloud",                             // 44
    "URL Index",                         // 45
    "User Agent",                        // 46
    "File Type",                         // 47
    "X-Forwarded-For",                   // 48
    "Referer",                           // 49
    "Sender",                            // 50
    "Subject",                           // 51
    "Recipient",                         // 52
    "Report ID",                         // 53
    "Device Group Hierarchy Level 1",    // 54
    "Device Group Hierarchy Level 2",    // 55
    "Device Group Hierarchy Level 3",    // 56
    "Device Group Hierarchy Level 4",    // 57
    "Virtual System Name",               // 58
    "Device Name",                       // 59
    "Source VM UUID",                    // 60
    "Destination VM UUID",               // 61
    "HTTP/2 Connection",                 // 62
    "High-Resolution-Timestamp",         // 63
    "SD-WAN-Cluster",                    // 64
    "SD-WAN-Device-Type",               // 65
    "SD-WAN-Cluster-Type",              // 66
    "SD-WAN-Site",                       // 67
    "Application-Subcategory",           // 68
    "Application-Category",              // 69
    "Application-Technology",            // 70
    "Application-Risk",                  // 71
    "Application-Characteristics",       // 72
    "Application-Container-Name",        // 73
    "Tunneled-Application",              // 74
    "is-SAAS-App",                       // 75
    "Application-Sanctioned-State",      // 76
    "X-Forwarded-For-Address",          // 77
    "Source-Device-Category",           // 78
    "Source-Device-Profile",            // 79
    "Nssai-Sst",                        // 80
    "Nssai-Sd",                         // 81
    "Partial-Hash",                     // 82
    "High-Resolution-Timestamp-2",      // 83
];

pub(super) const INTEGER_FIELDS: &[&str] = &[
    "Log Number",
    "Config Version",
    "Session ID",
    "Repeat Count",
    "Source Port",
    "Destination Port",
    "NAT Source Port",
    "NAT Destination Port",
    "Bytes",
    "Bytes Sent",
    "Bytes Received",
    "Packets",
    "Elapsed Time in seconds",
    "Sequence Number",
    "Packets Sent",
    "Packets Received",
    "Policy-ID",
    "Link-Switches",
    "Application-Risk",
    "PCAP ID",
    "URL Index",
    "Report ID",
];

pub(super) const FLOAT_FIELDS: &[&str] = &["High-Resolution-Timestamp", "High-Resolution-Timestamp-2"];
