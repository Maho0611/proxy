use crate::db::ProxyAccount;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn validate_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn derive_password(secret: &str, account_id: &str, credential_version: i32) -> String {
    let bytes = credential_bytes(secret, account_id, credential_version);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn verify_password(secret: &str, account: &ProxyAccount, password: &str) -> bool {
    let Ok(provided) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(password) else {
        return false;
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(credential_message(&account.id, account.credential_version).as_bytes());
    mac.verify_slice(&provided).is_ok()
}

pub fn derive_fixed_subscription_token(secret: &str, account_id: &str, version: i32) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("fixed-subscription:{account_id}:{version}").as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn verify_fixed_subscription_token(
    secret: &str,
    account_id: &str,
    version: i32,
    token: &str,
) -> bool {
    let Ok(provided) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("fixed-subscription:{account_id}:{version}").as_bytes());
    mac.verify_slice(&provided).is_ok()
}

fn credential_bytes(secret: &str, account_id: &str, credential_version: i32) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(credential_message(account_id, credential_version).as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn credential_message(account_id: &str, credential_version: i32) -> String {
    format!("{account_id}:{credential_version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(version: i32) -> ProxyAccount {
        ProxyAccount {
            id: "account-id".into(),
            label: "test".into(),
            username: "user_123".into(),
            owner_user_id: None,
            enabled: true,
            credential_version: version,
            last_used_at: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn username_rules_reserve_hyphen_for_filters() {
        assert!(validate_username("abc"));
        assert!(validate_username("user_123"));
        assert!(!validate_username("ab"));
        assert!(!validate_username("user-name"));
        assert!(!validate_username("user.name"));
    }

    #[test]
    fn password_is_stable_and_rotation_invalidates_old_version() {
        let secret = "01234567890123456789012345678901";
        let old = derive_password(secret, "account-id", 1);
        assert!(verify_password(secret, &account(1), &old));
        assert!(!verify_password(secret, &account(2), &old));
        let new = derive_password(secret, "account-id", 2);
        assert_ne!(old, new);
        assert!(verify_password(secret, &account(2), &new));
    }

    #[test]
    fn fixed_subscription_token_is_scoped_and_rotatable() {
        let secret = "01234567890123456789012345678901";
        let token = derive_fixed_subscription_token(secret, "account-id", 1);
        assert!(verify_fixed_subscription_token(
            secret,
            "account-id",
            1,
            &token
        ));
        assert!(!verify_fixed_subscription_token(
            secret,
            "other-account",
            1,
            &token
        ));
        assert!(!verify_fixed_subscription_token(
            secret,
            "account-id",
            2,
            &token
        ));
    }
}
