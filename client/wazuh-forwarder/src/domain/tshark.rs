use serde_json::{json, Value};

/// Normalize a tshark EK-format packet JSON into a unified log Value.
///
/// tshark EK output (`-T ek`) emits pairs:
///   {"index":{"_index":"packets-..."}}
///   {"timestamp":"<ms>","layers":{...}}
///
/// This function takes the *data* line (the one with "layers") and extracts
/// network flow fields into a flat structure compatible with the enrichment pipeline.
pub fn normalize_packet(packet: &Value) -> Option<Value> {
    let layers = packet.get("layers")?;
    let timestamp_ms: i64 = packet["timestamp"].as_str()?.parse().ok()?;

    let (src_ip, dst_ip, ip_version) = extract_ip(layers)?;
    let (src_port, dst_port, transport) = extract_transport(layers);
    let (frame_len, protocols, time_utc) = extract_frame(layers);

    Some(json!({
        "source_address": src_ip,
        "destination_address": dst_ip,
        "ip_version": ip_version,
        "Source Port": src_port,
        "Destination Port": dst_port,
        "ip_protocol": transport,
        "Bytes": frame_len,
        "timestamp_ms": timestamp_ms,
        "time_utc": time_utc,
        "protocols": protocols,
        "log_type": "tshark",
    }))
}

fn extract_ip(layers: &Value) -> Option<(String, String, u8)> {
    if let Some(ip) = layers.get("ip").and_then(Value::as_object) {
        let src = ip
            .get("ip_ip_src")
            .or_else(|| ip.get("ip_ip_src_host"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let dst = ip
            .get("ip_ip_dst")
            .or_else(|| ip.get("ip_ip_dst_host"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if src.is_empty() && dst.is_empty() {
            return None;
        }
        return Some((src, dst, 4));
    }
    if let Some(ip6) = layers.get("ipv6").and_then(Value::as_object) {
        let src = ip6
            .get("ipv6_ipv6_src")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let dst = ip6
            .get("ipv6_ipv6_dst")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if src.is_empty() && dst.is_empty() {
            return None;
        }
        return Some((src, dst, 6));
    }
    None
}

fn extract_transport(layers: &Value) -> (u16, u16, &'static str) {
    if let Some(tcp) = layers.get("tcp").and_then(Value::as_object) {
        let sp = parse_port(tcp.get("tcp_tcp_srcport").and_then(Value::as_str));
        let dp = parse_port(tcp.get("tcp_tcp_dstport").and_then(Value::as_str));
        return (sp, dp, "TCP");
    }
    if let Some(udp) = layers.get("udp").and_then(Value::as_object) {
        let sp = parse_port(udp.get("udp_udp_srcport").and_then(Value::as_str));
        let dp = parse_port(udp.get("udp_udp_dstport").and_then(Value::as_str));
        return (sp, dp, "UDP");
    }
    (0, 0, "OTHER")
}

fn extract_frame(layers: &Value) -> (u64, String, String) {
    let frame = match layers.get("frame").and_then(Value::as_object) {
        Some(f) => f,
        None => return (0, String::new(), String::new()),
    };
    let len = frame
        .get("frame_frame_len")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0u64);
    let protocols = frame
        .get("frame_frame_protocols")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let time_utc = frame
        .get("frame_frame_time_utc")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    (len, protocols, time_utc)
}

fn parse_port(s: Option<&str>) -> u16 {
    s.and_then(|v| v.parse().ok()).unwrap_or(0)
}
