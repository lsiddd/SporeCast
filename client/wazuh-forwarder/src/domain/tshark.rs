use serde_json::{json, Value};
use serde_json::map::Map;

/// Normalize a tshark EK-format packet JSON into a unified log Value.
///
/// tshark EK output (`-T ek`) emits pairs:
///   {"index":{"_index":"packets-..."}}
///   {"timestamp":"<ms>","layers":{...}}
///
/// All raw layer sub-objects are preserved verbatim as top-level keys.
/// Normalized flow fields (source_address, destination_address, etc.) are
/// set last so they always win on name collision with raw layer data.
pub fn normalize_packet(packet: &Value) -> Option<Value> {
    let layers = packet.get("layers")?;
    let timestamp_ms: i64 = packet["timestamp"].as_str()?.parse().ok()?;

    let (src_ip, dst_ip, ip_version) = extract_ip(layers)?;
    let (src_port, dst_port, transport) = extract_transport(layers);
    let (frame_len, protocols, time_utc) = extract_frame(layers);

    let mut out = Map::new();

    // Raw layers first — every layer sub-object preserved verbatim.
    if let Some(layers_obj) = layers.as_object() {
        for (layer_name, layer_data) in layers_obj {
            out.insert(layer_name.clone(), layer_data.clone());
        }
    }

    // Normalized flow fields override any same-named raw keys.
    out.insert("source_address".into(), Value::String(src_ip));
    out.insert("destination_address".into(), Value::String(dst_ip));
    out.insert("ip_version".into(), json!(ip_version));
    out.insert("Source Port".into(), json!(src_port));
    out.insert("Destination Port".into(), json!(dst_port));
    out.insert("ip_protocol".into(), Value::String(transport.to_string()));
    out.insert("Bytes".into(), json!(frame_len));
    out.insert("timestamp_ms".into(), json!(timestamp_ms));
    out.insert("time_utc".into(), Value::String(time_utc));
    out.insert("protocols".into(), Value::String(protocols));
    out.insert("log_type".into(), Value::String("tshark".into()));

    Some(Value::Object(out))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ipv6_tcp_tls_packet() -> Value {
        json!({
            "timestamp": "1780410711074",
            "layers": {
                "ipv6": {
                    "ipv6_ipv6_src": "2a04:4e42:3b::820",
                    "ipv6_ipv6_dst": "2804:1434:1de:2000:a34b:2c44:98ac:570c"
                },
                "tcp": {
                    "tcp_tcp_srcport": "443",
                    "tcp_tcp_dstport": "54768"
                },
                "frame": {
                    "frame_frame_len": "1476",
                    "frame_frame_protocols": "sll:ethertype:ipv6:tcp:tls",
                    "frame_frame_time_utc": "2026-06-02T14:31:51.074959726Z"
                }
            }
        })
    }

    fn ipv4_udp_packet() -> Value {
        json!({
            "timestamp": "1780410712000",
            "layers": {
                "ip": {
                    "ip_ip_src": "192.168.1.10",
                    "ip_ip_dst": "8.8.8.8"
                },
                "udp": {
                    "udp_udp_srcport": "60412",
                    "udp_udp_dstport": "53"
                },
                "frame": {
                    "frame_frame_len": "72",
                    "frame_frame_protocols": "sll:ethertype:ip:udp:dns",
                    "frame_frame_time_utc": "2026-06-02T14:31:52.000000000Z"
                }
            }
        })
    }

    #[test]
    fn normalizes_ipv6_tcp_tls_packet() {
        let packet = ipv6_tcp_tls_packet();
        let result = normalize_packet(&packet).expect("IPv6 TCP packet should normalize");

        assert_eq!(result["source_address"], "2a04:4e42:3b::820");
        assert_eq!(result["destination_address"], "2804:1434:1de:2000:a34b:2c44:98ac:570c");
        assert_eq!(result["ip_version"], 6);
        assert_eq!(result["Source Port"], 443);
        assert_eq!(result["Destination Port"], 54768);
        assert_eq!(result["ip_protocol"], "TCP");
        assert_eq!(result["Bytes"], 1476);
        assert_eq!(result["log_type"], "tshark");
        assert_eq!(result["timestamp_ms"], 1780410711074i64);
    }

    #[test]
    fn normalizes_ipv4_udp_packet() {
        let packet = ipv4_udp_packet();
        let result = normalize_packet(&packet).expect("IPv4 UDP packet should normalize");

        assert_eq!(result["source_address"], "192.168.1.10");
        assert_eq!(result["destination_address"], "8.8.8.8");
        assert_eq!(result["ip_version"], 4);
        assert_eq!(result["Destination Port"], 53);
        assert_eq!(result["ip_protocol"], "UDP");
        assert_eq!(result["log_type"], "tshark");
    }

    #[test]
    fn returns_none_for_packet_without_ip_layer() {
        let packet = json!({
            "timestamp": "123",
            "layers": {
                "frame": { "frame_frame_len": "60" }
            }
        });
        assert!(normalize_packet(&packet).is_none());
    }

    #[test]
    fn returns_none_for_missing_timestamp() {
        let packet = json!({
            "layers": {
                "ip": { "ip_ip_src": "1.2.3.4", "ip_ip_dst": "5.6.7.8" }
            }
        });
        assert!(normalize_packet(&packet).is_none());
    }
}
