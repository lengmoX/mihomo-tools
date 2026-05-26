pub mod socks;
pub mod shadowsocks;
pub mod vless;
pub mod trojan;
pub mod anytls;
pub mod hysteria2;
pub mod mihomo_yaml;

use crate::models::{CommandResult, ParseOutboundUrlResult};
use crate::utils::percent_decode;

pub use socks::parse_socks_url;

pub fn parse_outbound_url_value(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let trimmed = input.trim();
    
    // Check if it's a URL first by scheme matching
    let is_url = trimmed.contains("://") && !trimmed.starts_with("socks://") && !trimmed.starts_with("socks5://");
    
    if is_url {
        let normalized = normalize_proxy_url(input);
        if let Some((scheme, _)) = normalized.split_once("://") {
            let scheme_lower = scheme.to_ascii_lowercase();
            match scheme_lower.as_str() {
                "socks" | "socks5" => return socks::parse_socks_url(&normalized),
                "vless" => return vless::parse_vless_url(&normalized),
                "ss" => return shadowsocks::parse_shadowsocks_url(&normalized),
                "trojan" => return trojan::parse_trojan_url(&normalized),
                "anytls" => return anytls::parse_anytls_url(&normalized),
                "hy2" | "hysteria2" => return hysteria2::parse_hysteria2_url(&normalized),
                _ => {} // Fall through to YAML if URL scheme is unsupported
            }
        }
    } else {
        // Try raw SOCKS formats first
        if let Some(res) = socks::try_parse_raw_socks(trimmed) {
            return Ok(res);
        }
    }
    
    // If it's not parsed as a URL/SOCKS, attempt Clash/Mihomo YAML parser
    match mihomo_yaml::parse_mihomo_yaml(input) {
        Ok(res) => Ok(res),
        Err(e) => {
            if is_url {
                Err(format!("Failed to parse URL or YAML: {e}"))
            } else {
                Err(format!("Pasted text is neither a valid SOCKS string nor YAML/JSON: {e}"))
            }
        }
    }
}

pub fn optional_query_value(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key: &str,
) -> Option<String> {
    query
        .iter()
        .find(|(name, _)| name.as_ref() == key)
        .map(|(_, value)| value.to_string())
}

pub fn unsupported_query_warnings(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    supported: &[&str],
) -> Vec<String> {
    query
        .iter()
        .filter(|(name, _)| !supported.contains(&name.as_ref()))
        .map(|(name, _)| format!("Ignored unsupported query parameter '{name}'"))
        .collect()
}

pub fn parse_fragment(fragment: Option<&str>) -> CommandResult<Option<String>> {
    fragment
        .map(percent_decode)
        .transpose()
        .map(|fragment| fragment.filter(|value| !value.is_empty()))
}

pub fn normalize_proxy_url(input: &str) -> String {
    let trimmed = input.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return trimmed.to_string();
    };

    if let Some(at_idx) = find_credentials_separator(rest) {
        let credentials = &rest[..at_idx];
        let host_and_more = &rest[at_idx..];

        const SAFE_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b'#')
            .add(b'?')
            .add(b'{')
            .add(b'}')
            .add(b'[')
            .add(b']')
            .add(b'/')
            .add(b'\\')
            .add(b'@');

        let encoded_credentials = percent_encoding::utf8_percent_encode(credentials, SAFE_ENCODE_SET).to_string();
        format!("{}://{}{}", scheme, encoded_credentials, host_and_more)
    } else {
        trimmed.to_string()
    }
}

fn find_credentials_separator(rest: &str) -> Option<usize> {
    let mut at_indices = Vec::new();
    for (i, c) in rest.char_indices() {
        if c == '@' {
            at_indices.push(i);
        }
    }

    for &idx in at_indices.iter() {
        let after = &rest[idx + 1..];
        let end_idx = after.find(['/', '?', '#']).unwrap_or(after.len());
        let host_port_part = &after[..end_idx];

        if host_port_part.is_empty() {
            continue;
        }

        let is_valid = host_port_part.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']'
        });

        if is_valid {
            return Some(idx);
        }
    }
    None
}
