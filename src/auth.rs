use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// What the client sends: HMAC-SHA256(secret, nonce), hex encoded.
pub fn mac_hex(secret: &str, nonce: &str) -> anyhow::Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(nonce.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time check of a hex mac against the expected value.
pub fn verify(secret: &str, nonce: &str, got_hex: &str) -> anyhow::Result<bool> {
    let Ok(got) = hex::decode(got_hex) else {
        return Ok(false);
    };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(nonce.as_bytes());
    Ok(mac.verify_slice(&got).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_mac_verifies() {
        let mac = mac_hex("hunter2", "nonce-1").unwrap();
        assert!(verify("hunter2", "nonce-1", &mac).unwrap());
    }

    #[test]
    fn wrong_secret_rejected() {
        let mac = mac_hex("hunter2", "nonce-1").unwrap();
        assert!(!verify("hunter3", "nonce-1", &mac).unwrap());
    }

    #[test]
    fn replayed_mac_fails_on_a_new_nonce() {
        let mac = mac_hex("hunter2", "nonce-1").unwrap();
        assert!(!verify("hunter2", "nonce-2", &mac).unwrap());
    }

    #[test]
    fn garbage_rejected() {
        assert!(!verify("hunter2", "nonce-1", "not-hex!!").unwrap());
    }
}
