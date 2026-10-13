use std::sync::OnceLock;
use tracing::{debug, error, warn};

static PASSWORD: OnceLock<String> = OnceLock::new();

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

fn get_password() -> String {
    if let Some(gatewayid) = get_gatewayid() {
        if let Some(password) = gatewayid.split('-').next() {
            return password.to_string();
        }
    }
    warn!("Failed to derive password from gateway ID, falling back to development password");
    "password-for-dev".to_string()
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

    let password = PASSWORD.get_or_init(get_password);
    let credentials_valid = credentials.ends_with(format!(":{password}").as_str());

    if credentials_valid {
        debug!("Authorization successful");
    } else {
        error!("Invalid credentials provided");
    }

    credentials_valid
}
