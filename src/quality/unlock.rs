use serde_json::{Map, Value};

pub const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct UnlockReport {
    pub checks: Value,
    pub google_accessible: bool,
    pub chatgpt_accessible: bool,
    pub google_detail: String,
    pub chatgpt_detail: String,
}

#[derive(Debug)]
struct UnlockCheck {
    available: Option<bool>,
    status: String,
    status_code: Option<u16>,
    region: Option<String>,
    detail: String,
}

impl UnlockCheck {
    fn available(code: Option<u16>, region: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            available: Some(true),
            status: "available".into(),
            status_code: code,
            region,
            detail: detail.into(),
        }
    }

    fn unavailable(code: Option<u16>, region: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            available: Some(false),
            status: "unavailable".into(),
            status_code: code,
            region,
            detail: detail.into(),
        }
    }

    fn limited(
        status: &str,
        available: bool,
        code: Option<u16>,
        region: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            available: Some(available),
            status: status.into(),
            status_code: code,
            region,
            detail: detail.into(),
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            available: None,
            status: "error".into(),
            status_code: None,
            region: None,
            detail: detail.into(),
        }
    }

    fn as_json(&self) -> Value {
        serde_json::json!({
            "available": self.available,
            "status": self.status,
            "status_code": self.status_code,
            "region": self.region,
            "detail": self.detail,
        })
    }
}

struct HttpSnapshot {
    status: u16,
    final_url: String,
    body: String,
}

pub async fn check_all(client: &reqwest::Client) -> UnlockReport {
    let (google, chatgpt, sora, gemini, copilot, claude, netflix, youtube_premium, spotify, tiktok) = tokio::join!(
        check_google(client),
        check_chatgpt(client),
        check_sora(client),
        check_gemini(client),
        check_copilot(client),
        check_claude(client),
        check_netflix(client),
        check_youtube_premium(client),
        check_spotify(client),
        check_tiktok(client),
    );

    let google_accessible = google.available == Some(true);
    let chatgpt_accessible = chatgpt.available == Some(true);
    let google_detail = google.detail.clone();
    let chatgpt_detail = chatgpt.detail.clone();
    let mut checks = Map::new();
    for (name, result) in [
        ("google", google),
        ("chatgpt", chatgpt),
        ("sora", sora),
        ("gemini", gemini),
        ("copilot", copilot),
        ("claude", claude),
        ("netflix", netflix),
        ("youtube_premium", youtube_premium),
        ("spotify", spotify),
        ("tiktok", tiktok),
    ] {
        checks.insert(name.into(), result.as_json());
    }

    UnlockReport {
        checks: Value::Object(checks),
        google_accessible,
        chatgpt_accessible,
        google_detail,
        chatgpt_detail,
    }
}

async fn check_google(client: &reqwest::Client) -> UnlockCheck {
    match client
        .get("https://www.google.com/generate_204")
        .send()
        .await
    {
        Ok(response) => {
            let code = response.status().as_u16();
            if code == 204 || response.status().is_success() {
                UnlockCheck::available(Some(code), None, format!("http {code}"))
            } else {
                UnlockCheck::unavailable(Some(code), None, format!("http {code}"))
            }
        }
        Err(error) => UnlockCheck::error(shorten(error.to_string())),
    }
}

async fn check_chatgpt(client: &reqwest::Client) -> UnlockCheck {
    let (web, ios) = tokio::join!(
        get_snapshot(client, "https://chatgpt.com/"),
        get_snapshot(client, "https://ios.chat.openai.com/")
    );
    let web = match web {
        Ok(result) => result,
        Err(error) => return UnlockCheck::error(error),
    };
    let body_lower = web.body.to_ascii_lowercase();
    let web_available =
        success_or_redirect(web.status) && web.status != 403 && !contains_region_block(&body_lower);
    let ios_body = ios
        .as_ref()
        .map(|result| result.body.to_ascii_lowercase())
        .unwrap_or_default();
    let unsupported = ios_body.contains("unsupported_country_region_territory")
        || ios_body.contains("blocked_why_headline");
    let disallowed_isp =
        ios_body.contains("cf_details") && (ios_body.contains("(1)") || ios_body.contains("(2)"));
    let region = if web_available {
        trace_region(client, "https://chatgpt.com/cdn-cgi/trace").await
    } else {
        None
    };

    if web_available && disallowed_isp {
        UnlockCheck::limited(
            "web_only",
            true,
            Some(web.status),
            region,
            "web available; app reports disallowed ISP",
        )
    } else if web_available {
        UnlockCheck::available(Some(web.status), region, format!("http {}", web.status))
    } else if unsupported {
        UnlockCheck::unavailable(Some(web.status), None, "unsupported region or blocked")
    } else if disallowed_isp {
        UnlockCheck::unavailable(Some(web.status), None, "disallowed ISP")
    } else {
        UnlockCheck::unavailable(Some(web.status), None, format!("http {}", web.status))
    }
}

async fn check_sora(client: &reqwest::Client) -> UnlockCheck {
    match get_snapshot(client, "https://sora.com/").await {
        Ok(result)
            if success_or_redirect(result.status) && !contains_region_block(&result.body) =>
        {
            let region = trace_region(client, "https://sora.com/cdn-cgi/trace").await;
            UnlockCheck::available(
                Some(result.status),
                region,
                format!("http {}", result.status),
            )
        }
        Ok(result) => {
            UnlockCheck::unavailable(Some(result.status), None, format!("http {}", result.status))
        }
        Err(error) => UnlockCheck::error(error),
    }
}

async fn check_gemini(client: &reqwest::Client) -> UnlockCheck {
    let request = client
        .post("https://gemini.google.com/_/BardChatUi/data/batchexecute")
        .header("accept-language", "en-US")
        .form(&[(
            "f.req",
            r#"[[["K4WWud","[[0],[\"en-US\"]]",null,"generic"]]]"#,
        )]);
    match request.send().await {
        Ok(response) => match snapshot(response).await {
            Ok(result) if success_or_redirect(result.status) && result.body.contains("K4WWud") => {
                UnlockCheck::available(
                    Some(result.status),
                    extract_escaped_region(&result.body),
                    format!("http {}", result.status),
                )
            }
            Ok(result) if result.status == 403 => {
                UnlockCheck::unavailable(Some(403), None, "http 403")
            }
            Ok(result) => {
                UnlockCheck::unavailable(Some(result.status), None, "location response missing")
            }
            Err(error) => UnlockCheck::error(error),
        },
        Err(error) => UnlockCheck::error(shorten(error.to_string())),
    }
}

async fn check_copilot(client: &reqwest::Client) -> UnlockCheck {
    let (page, api) = tokio::join!(
        get_snapshot(client, "https://copilot.microsoft.com/"),
        get_snapshot(
            client,
            "https://copilot.microsoft.com/turing/conversation/chats?bundleVersion=1.1342.3-cplt.12"
        )
    );
    let page = match page {
        Ok(result) => result,
        Err(error) => return UnlockCheck::error(error),
    };
    let region = extract_string_after(&page.body, "RevIpCC:\"")
        .or_else(|| extract_string_after(&page.body, "RevIpCC:\\\""))
        .map(|value| value.to_ascii_uppercase());
    match api {
        Ok(result) => {
            let success = serde_json::from_str::<Value>(&result.body)
                .ok()
                .and_then(|value| {
                    value
                        .get("result")
                        .and_then(|value| value.get("value"))
                        .and_then(Value::as_str)
                        .map(|value| value.eq_ignore_ascii_case("success"))
                })
                .unwrap_or(false);
            if success {
                UnlockCheck::available(Some(result.status), region, "conversation API success")
            } else {
                UnlockCheck::unavailable(Some(result.status), region, "conversation API denied")
            }
        }
        Err(error) => UnlockCheck::error(error),
    }
}

async fn check_claude(client: &reqwest::Client) -> UnlockCheck {
    match get_snapshot(client, "https://claude.ai/").await {
        Ok(result)
            if success_or_redirect(result.status)
                && !result
                    .final_url
                    .to_ascii_lowercase()
                    .contains("unavailable")
                && !contains_region_block(&result.body) =>
        {
            UnlockCheck::available(Some(result.status), None, format!("http {}", result.status))
        }
        Ok(result) => {
            UnlockCheck::unavailable(Some(result.status), None, format!("http {}", result.status))
        }
        Err(error) => UnlockCheck::error(error),
    }
}

async fn check_netflix(client: &reqwest::Client) -> UnlockCheck {
    let (first, second) = tokio::join!(
        get_snapshot(client, "https://www.netflix.com/title/81280792"),
        get_snapshot(client, "https://www.netflix.com/title/70143836")
    );
    if first.is_err() && second.is_err() {
        return UnlockCheck::error("both title checks failed");
    }
    let snapshots = [first.ok(), second.ok()];
    let full_catalog = snapshots
        .iter()
        .flatten()
        .any(|result| result.body.contains("og:video") || result.body.contains("playerUrl"));
    let region = snapshots
        .iter()
        .flatten()
        .find_map(|result| extract_json_string(&result.body, "requestCountry"));
    let code = snapshots
        .iter()
        .flatten()
        .next()
        .map(|result| result.status);
    if full_catalog {
        UnlockCheck::available(code, region, "non-original title available")
    } else {
        UnlockCheck::limited("originals_only", false, code, region, "originals only")
    }
}

async fn check_youtube_premium(client: &reqwest::Client) -> UnlockCheck {
    let request = client
        .get("https://www.youtube.com/premium")
        .header("accept-language", "en-US,en;q=0.9");
    match request.send().await {
        Ok(response) => match snapshot(response).await {
            Ok(result) => {
                let region = extract_json_string(&result.body, "countryCode");
                if result.body.contains("www.google.cn") {
                    return UnlockCheck::unavailable(
                        Some(result.status),
                        Some("CN".into()),
                        "redirected to google.cn",
                    );
                }
                let available = result.body.contains("purchaseButtonOverride")
                    || result.body.contains("Start trial")
                    || region.is_some();
                if available && success_or_redirect(result.status) {
                    UnlockCheck::available(Some(result.status), region, "premium page available")
                } else {
                    UnlockCheck::unavailable(Some(result.status), region, "premium offer missing")
                }
            }
            Err(error) => UnlockCheck::error(error),
        },
        Err(error) => UnlockCheck::error(shorten(error.to_string())),
    }
}

async fn check_spotify(client: &reqwest::Client) -> UnlockCheck {
    match get_snapshot(client, "https://www.spotify.com/signup").await {
        Ok(result) => {
            let region = extract_json_string(&result.body, "geoCountry")
                .or_else(|| extract_json_string(&result.body, "geoCountryMarket"));
            if region.is_some() && success_or_redirect(result.status) {
                UnlockCheck::available(Some(result.status), region, "signup region detected")
            } else {
                UnlockCheck::unavailable(Some(result.status), None, "signup region missing")
            }
        }
        Err(error) => UnlockCheck::error(error),
    }
}

async fn check_tiktok(client: &reqwest::Client) -> UnlockCheck {
    let (page, region_response) =
        tokio::join!(get_snapshot(client, "https://www.tiktok.com/"), async {
            let response = client
                .post("https://www.tiktok.com/passport/web/store_region/")
                .send()
                .await
                .map_err(|error| shorten(error.to_string()))?;
            snapshot(response).await
        });
    let page = match page {
        Ok(result) => result,
        Err(error) => return UnlockCheck::error(error),
    };
    let region = region_response.ok().and_then(|result| {
        serde_json::from_str::<Value>(&result.body)
            .ok()
            .and_then(|value| {
                value
                    .get("data")
                    .and_then(|value| value.get("store_region"))
                    .and_then(Value::as_str)
                    .map(|value| value.to_ascii_uppercase())
            })
    });
    let final_url = page.final_url.to_ascii_lowercase();
    let redirected = final_url.contains("/about")
        || final_url.contains("/status")
        || final_url.contains("landing");
    if redirected || !success_or_redirect(page.status) {
        UnlockCheck::unavailable(Some(page.status), region, "redirected to restricted page")
    } else {
        UnlockCheck::available(Some(page.status), region, format!("http {}", page.status))
    }
}

async fn get_snapshot(client: &reqwest::Client, url: &str) -> Result<HttpSnapshot, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| shorten(error.to_string()))?;
    snapshot(response).await
}

async fn snapshot(mut response: reqwest::Response) -> Result<HttpSnapshot, String> {
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let mut bytes = Vec::new();
    while bytes.len() < MAX_RESPONSE_BYTES {
        let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| shorten(error.to_string()))?
        else {
            break;
        };
        let remaining = MAX_RESPONSE_BYTES - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            break;
        }
    }
    Ok(HttpSnapshot {
        status,
        final_url,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

async fn trace_region(client: &reqwest::Client, url: &str) -> Option<String> {
    let result = get_snapshot(client, url).await.ok()?;
    result
        .body
        .lines()
        .find_map(|line| line.strip_prefix("loc="))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_uppercase)
}

fn success_or_redirect(status: u16) -> bool {
    (200..400).contains(&status)
}

fn contains_region_block(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("unsupported_country")
        || body.contains("unsupported region")
        || body.contains("unavailable in your country")
        || body.contains("not available in your country")
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    for marker in [
        format!("\"{key}\":\""),
        format!("\"{key}\": \""),
        format!("\\\"{key}\\\":\\\""),
    ] {
        if let Some(value) = extract_string_after(body, &marker) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn extract_string_after(body: &str, marker: &str) -> Option<String> {
    let rest = body.split_once(marker)?.1;
    let end = rest.find(['"', '\\']).unwrap_or(rest.len());
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn extract_escaped_region(body: &str) -> Option<String> {
    for marker in ["[[\\\"", "[[\""] {
        let mut remaining = body;
        while let Some((_, rest)) = remaining.split_once(marker) {
            let candidate: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphabetic())
                .collect();
            if candidate.len() == 2 {
                return Some(candidate.to_ascii_uppercase());
            }
            remaining = rest;
        }
    }
    None
}

fn shorten(detail: String) -> String {
    const MAX_LEN: usize = 160;
    if detail.chars().count() <= MAX_LEN {
        detail
    } else {
        detail.chars().take(MAX_LEN).collect::<String>() + "..."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_plain_and_escaped_regions() {
        assert_eq!(
            extract_json_string(r#"{"countryCode":"US"}"#, "countryCode").as_deref(),
            Some("US")
        );
        assert_eq!(
            extract_escaped_region(r#"x [[\"JP\",\"S"#).as_deref(),
            Some("JP")
        );
    }

    #[test]
    fn detects_common_region_block_messages() {
        assert!(contains_region_block("unsupported_country"));
        assert!(contains_region_block("Unavailable in your country"));
        assert!(!contains_region_block("Welcome to the service"));
    }
}
