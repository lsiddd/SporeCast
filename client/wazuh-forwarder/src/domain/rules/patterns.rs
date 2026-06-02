use regex::Regex;
use std::collections::HashMap;

use super::CORRELATION_RULES;

fn compile_regex(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(err) => panic!("failed to compile regex {pattern:?}: {err}"),
    }
}

lazy_static::lazy_static! {
    pub static ref IP_REGEX: Regex = compile_regex(
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    );

    pub static ref DOMAIN_REGEX: Regex = compile_regex(
        r"(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    );

    pub static ref HASH_REGEX: Regex = compile_regex(
        r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})\b"
    );

    pub static ref URL_REGEX: Regex = compile_regex(
        r"(?i)(?:https?|ftp)://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*"
    );

    pub static ref CSV_TIMESTAMP_PATTERN: Regex = compile_regex(r",\d{4}/");

    pub static ref CORRELATION_RULES_COMPILED: Vec<(&'static str, Regex)> =
        CORRELATION_RULES.iter().map(|(name, pattern)| {
            (*name, compile_regex(pattern))
        }).collect();

    pub static ref SUSPICIOUS_PATTERNS_COMPILED: HashMap<String, Regex> = {
        let mut patterns = HashMap::new();

        patterns.insert("base64_encoded".to_string(),
            compile_regex(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"));
        patterns.insert("hex_encoded".to_string(),
            compile_regex(r"(?:\\x[0-9a-fA-F]{2}){10,}"));
        patterns.insert("unicode_encoded".to_string(),
            compile_regex(r"(?:\\u[0-9a-fA-F]{4}){5,}"));

        patterns.insert("obfuscated_powershell".to_string(),
            compile_regex(r"(?i)powershell.*[-/][eE](?:ncodedcommand|nc)?\s+[a-zA-Z0-9+/=]{20,}"));
        patterns.insert("obfuscated_script".to_string(),
            compile_regex(r"(?i)(?:cmd|powershell|bash|sh).*[{()}$`|&;]{3,}"));

        patterns.insert("sql_injection".to_string(),
            compile_regex(r"(?i)(?:union\s+select|drop\s+table|insert\s+into|update\s+set|delete\s+from|'|\s+or\s+1=1|\s+and\s+1=1)"));
        patterns.insert("xss_attempt".to_string(),
            compile_regex(r"(?i)(?:<script|javascript:|onload=|onerror=|onclick=|onmouseover=)"));
        patterns.insert("command_injection".to_string(),
            compile_regex(r"(?i)(?:;|\|\||&&|`|\$\(|\$\{|%[0-9a-fA-F]\{2\})"));
        patterns.insert("directory_traversal".to_string(),
            compile_regex(r"(?i)(?:\.\./|\.\.\\|/etc/|c:\\|%2e%2e%2f|%2e%2e%5c)"));

        patterns.insert("suspicious_user_agent".to_string(),
            compile_regex(r"(?i)(?:curl|wget|python-requests|urllib|httpclient|bot|scanner|crawler|sqlmap)"));

        patterns.insert("crypto_mining".to_string(),
            compile_regex(r"(?i)(?:stratum|mining|coinminer|cryptonight|xmrig|monero|bitcoin)"));
        patterns.insert("malware_family".to_string(),
            compile_regex(r"(?i)(?:emotet|trickbot|qakbot|dridex|lokibot|azorult|formbook|hawkeye|nanocore)"));

        patterns
    };
}
