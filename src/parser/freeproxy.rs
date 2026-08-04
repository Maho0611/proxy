use super::ProxyConfig;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FreeProxyDocument {
    Feed { data: Vec<Value> },
    Sources(HashMap<String, Vec<Value>>),
}

pub fn parse(content: &str) -> Vec<ProxyConfig> {
    let trimmed = content.trim();
    if !trimmed.starts_with('{') {
        return vec![];
    }

    let document: FreeProxyDocument = match serde_json::from_str(trimmed) {
        Ok(document) => document,
        Err(error) => {
            tracing::debug!("Content is not FreeProxy JSON: {error}");
            return vec![];
        }
    };
    let entries = match document {
        FreeProxyDocument::Feed { data } => data,
        FreeProxyDocument::Sources(sources) => sources.into_values().flatten().collect(),
    };

    entries.into_iter().flat_map(parse_entry).collect()
}

fn parse_entry(entry: Value) -> Vec<ProxyConfig> {
    let Some(entry) = entry.as_object() else {
        return vec![];
    };
    let Some(ip) = entry
        .get("ip")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
    else {
        return vec![];
    };
    let Some(port) = entry.get("port").and_then(parse_port) else {
        return vec![];
    };
    let Some(protocols) = entry.get("protocol").and_then(Value::as_str) else {
        return vec![];
    };
    let country = entry
        .get("country")
        .or_else(|| entry.get("country_code"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|country| !country.is_empty());
    let host = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    let mut seen = HashSet::new();

    protocols
        .split(',')
        .filter_map(|protocol| {
            let protocol = protocol.trim().to_ascii_lowercase();
            if !matches!(protocol.as_str(), "http" | "https" | "socks4" | "socks5")
                || !seen.insert(protocol.clone())
            {
                return None;
            }
            let uri = format!("{protocol}://{host}:{port}");
            let mut proxy = super::v2ray::parse_uri(&uri)?;
            let label = match country {
                Some(country) => format!("{}/{country}", protocol.to_ascii_uppercase()),
                None => protocol.to_ascii_uppercase(),
            };
            proxy.name = format!("[{label}] {ip}:{port}");
            Some(proxy)
        })
        .collect()
}

fn parse_port(value: &Value) -> Option<u16> {
    let port = match value {
        Value::Number(number) => u16::try_from(number.as_u64()?).ok()?,
        Value::String(port) => port.trim().parse().ok()?,
        _ => return None,
    };
    (port > 0).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_official_feed_and_expands_multi_protocol_entries() {
        let content = r#"{
          "updated_at": "2026-08-04 14:27:51 UTC",
          "count": 5,
          "data": [
            {"ip":"192.0.2.1","port":8080,"protocol":"Http","country":"US"},
            {"ip":"192.0.2.2","port":443,"protocol":"Https","country":"JP"},
            {"ip":"192.0.2.3","port":1080,"protocol":"Socks4, Socks5","country":"DE"},
            {"ip":"192.0.2.4","port":0,"protocol":"Http","country":"GB"},
            {"ip":"192.0.2.5","port":21,"protocol":"FTP","country":"FR"}
          ]
        }"#;

        let proxies = parse(content);

        assert_eq!(proxies.len(), 4);
        assert!(proxies
            .iter()
            .any(|proxy| proxy.name == "[HTTP/US] 192.0.2.1:8080"));
        let https = proxies
            .iter()
            .find(|proxy| proxy.name.starts_with("[HTTPS/JP]"))
            .unwrap();
        assert_eq!(https.singbox_outbound["tls"]["enabled"], true);
        let socks_versions: Vec<_> = proxies
            .iter()
            .filter_map(|proxy| proxy.singbox_outbound["version"].as_str())
            .collect();
        assert!(socks_versions.contains(&"4a"));
        assert!(socks_versions.contains(&"5"));
    }

    #[test]
    fn parses_source_grouped_exports_with_string_ports() {
        let content = r#"{
          "ExampleProxiedSession": [
            {"source":"ExampleProxiedSession","protocol":"socks5","ip":"2001:db8::1","port":"1080","country_code":"NL"},
            {"protocol":"http","ip":"192.0.2.10","port":{"invalid":true}},
            "malformed"
          ]
        }"#;

        let proxies = parse(content);

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name, "[SOCKS5/NL] 2001:db8::1:1080");
        assert_eq!(proxies[0].server, "2001:db8::1");
    }

    #[test]
    fn rejects_unrelated_or_invalid_json() {
        assert!(parse("not json").is_empty());
        assert!(parse(r#"{"data":"wrong shape"}"#).is_empty());
    }
}
