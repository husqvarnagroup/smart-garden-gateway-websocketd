use openssl::base64::encode_block;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use std::sync::OnceLock;
use tracing::{debug, error, warn};

const PASSWORD_PATH: &str = "/etc/gateway-config-interface/password";

static GATEWAY_ID: OnceLock<Option<String>> = OnceLock::new();
static PASSWORD_HASH: OnceLock<String> = OnceLock::new();

fn get_gatewayid() -> Option<String> {
    if let Ok(result) = std::process::Command::new("fw_printenv")
        .arg("-n")
        .arg("gatewayid")
        .output()
    {
        if result.status.success() {
            if let Ok(gatewayid) = std::str::from_utf8(&result.stdout) {
                return Some(gatewayid.trim().to_string());
            }
        }
    }
    None
}

fn get_password_hash_from_gatewayid() -> String {
    if let Some(gatewayid) = get_gatewayid() {
        if let Some(password) = gatewayid.split('-').next() {
            return calculate_password_hash(password);
        }
    }
    warn!("Failed to derive password from gateway ID, falling back to development password");
    calculate_password_hash("password-for-dev")
}

async fn get_password_hash_from_file() -> Option<String> {
    match tokio::fs::read_to_string(PASSWORD_PATH).await {
        Ok(hash_from_file) => Some(hash_from_file),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        // Any other error must not fall back to the default password
        Err(_) => {
            error!("Failed to read password from {PASSWORD_PATH}");
            Some("invalid".to_string())
        }
    }
}

async fn get_password_hash() -> String {
    get_password_hash_from_file()
        .await
        .unwrap_or_else(get_password_hash_from_gatewayid)
}

fn calculate_password_hash(password: &str) -> String {
    const PASSWORD_HASH_ITERATIONS: usize = 2048;
    const PASSWORD_HASH_LEN: usize = 20; // SHA1 output length in bytes
    let mut digest = [0u8; PASSWORD_HASH_LEN];
    let salt = match GATEWAY_ID.get().expect("GATEWAY_ID not initialized") {
        Some(gwid) => gwid.as_bytes(),
        None => b"",
    };
    // The arguments need to match the ones used in the config backend
    pbkdf2_hmac(
        password.as_bytes(),
        salt,
        PASSWORD_HASH_ITERATIONS,
        MessageDigest::sha1(),
        &mut digest,
    )
    .expect("Failed to calculate password hash");
    encode_block(&digest)
}

#[allow(clippy::module_name_repetitions)]
pub async fn init_auth() {
    GATEWAY_ID
        .set(get_gatewayid())
        .expect("Failed to initialize GATEWAY_ID");
    PASSWORD_HASH
        .set(get_password_hash().await)
        .expect("PASSWORD_HASH already initialized");
}

#[allow(clippy::module_name_repetitions)]
pub fn check_basic_auth(auth_header: Option<&str>) -> bool {
    let Some(auth) = auth_header else {
        debug!("No authorization header provided");
        return false;
    };

    let Some(encoded) = auth.strip_prefix("Basic ") else {
        debug!("Authorization header missing 'Basic ' prefix");
        return false;
    };

    let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
    else {
        debug!("Failed to decode base64 authorization");
        return false;
    };

    let Ok(credentials) = String::from_utf8(decoded) else {
        debug!("Authorization credentials not valid UTF-8");
        return false;
    };

    let Some((_, input_password)) = credentials.split_once(':') else {
        error!("Failed to extract password from input credentials");
        return false;
    };

    let input_password_hash = calculate_password_hash(input_password);
    let password_hash = PASSWORD_HASH.get().expect("PASSWORD_HASH not initialized");
    let credentials_valid = input_password_hash == *password_hash;

    if credentials_valid {
        debug!("Authorization successful");
    } else {
        error!("Invalid credentials provided");
    }

    credentials_valid
}
