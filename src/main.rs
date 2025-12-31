use futures_util::{SinkExt, StreamExt};
use native_tls::Identity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_native_tls::TlsAcceptor;
use tokio_tungstenite::tungstenite::http::Response;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

const LEMONBEATD_COMMAND_PATH: &str = "/tmp/lemonbeatd-command.ipc";
const LEMONBEATD_EVENT_PATH: &str = "/tmp/lemonbeatd-event.ipc";
const LWM2MSERVER_COMMAND_PATH: &str = "/tmp/lwm2mserver-command.ipc";
const LWM2MSERVER_EVENT_PATH: &str = "/tmp/lwm2mserver-event.ipc";
const PORT: u16 = 8443;
const TLS_CERT_PATH: &str = "/etc/gateway-config-interface/cert.pem";
const TLS_KEY_PATH: &str = "/etc/gateway-config-interface/key.pem";
const TLS_CERT_PATH_DEV: &str = "./dev-cert.pem";
const TLS_KEY_PATH_DEV: &str = "./dev-key.pem";

static PASSWORD: OnceLock<String> = OnceLock::new();

#[derive(Debug, Deserialize, Default, Serialize, Clone)]
struct MsgEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

#[derive(Debug, Deserialize, Default, Serialize, Clone)]
struct Msg {
    #[serde(skip_serializing_if = "Option::is_none")]
    entity: Option<MsgEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success: Option<bool>,
}

enum ServiceTarget {
    Lemonbeatd,
    Lwm2mserver,
    None,
}

impl Msg {
    fn from_json(json: &str) -> Result<Self, String> {
        match serde_json::from_str::<Vec<Msg>>(json) {
            Ok(vec) if !vec.is_empty() => {
                if vec.len() > 1 {
                    warn!("Parsed array with multiple messages, only the first will be processed: {vec:?}");
                }
                Ok(vec[0].clone())
            }
            Ok(_) => Err("Failed to parse empty array".to_string()),
            Err(e) => Err(format!("Failed to parse JSON: {json}, error: {e}")),
        }
    }

    fn from_error_msg(error: &str) -> Self {
        Msg {
            payload: Some(HashMap::from([(
                "error".to_string(),
                serde_json::Value::String(error.to_string()),
            )])),
            success: Some(false),
            ..Default::default()
        }
    }

    fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&vec![self])
    }

    fn route_target(&self) -> ServiceTarget {
        let Some(entity) = &self.entity else {
            error!("Cannot forward message missing entity: {:?}", self);
            return ServiceTarget::None;
        };

        if let Some(service) = &entity.service {
            if service == "lemonbeatd" {
                return ServiceTarget::Lemonbeatd;
            } else if service == "lwm2mserver" {
                return ServiceTarget::Lwm2mserver;
            }
        }

        // TODO: remove
        if entity.path.contains("lemonbeat") {
            return ServiceTarget::Lemonbeatd;
        }
        ServiceTarget::None
    }
}

async fn load_tls_identity() -> Result<Identity, anyhow::Error> {
    let (cert_path, key_path) = if tokio::fs::try_exists(TLS_CERT_PATH).await.unwrap_or(false)
        && tokio::fs::try_exists(TLS_KEY_PATH).await.unwrap_or(false)
    {
        debug!("Using TLS certificate from /etc/gateway-config-interface/");
        (TLS_CERT_PATH, TLS_KEY_PATH)
    } else {
        warn!("No TLS certificate found in /etc/gateway-config-interface/, using development certificate");
        (TLS_CERT_PATH_DEV, TLS_KEY_PATH_DEV)
    };

    let cert = tokio::fs::read(cert_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read certificate from {}: {}", cert_path, e))?;
    let key = tokio::fs::read(key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read key from {}: {}", key_path, e))?;

    Identity::from_pkcs8(&cert, &key)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS identity: {e}"))
}

fn get_password() -> String {
    if let Ok(result) = std::process::Command::new("fw_printenv")
        .arg("-n")
        .arg("gatewayid")
        .output()
    {
        if result.status.success() {
            if let Ok(gatewayid) = std::str::from_utf8(&result.stdout) {
                if let Some(password) = gatewayid.trim().split('-').next() {
                    return password.to_string();
                }
            }
        }
    }
    warn!("Failed to derive password from gateway ID, falling back to dev password");
    "password-for-dev".to_string()
}

fn check_basic_auth(auth_header: Option<&str>) -> bool {
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

    let password = PASSWORD.get().expect("PASSWORD not initialized");
    let credentials_valid = credentials.ends_with(format!(":{password}").as_str());

    if credentials_valid {
        debug!("Authorization successful");
    } else {
        error!("Invalid credentials provided");
    }

    credentials_valid
}

async fn ws_sender<S>(
    mut ws_write: S,
    mut rx: broadcast::Receiver<Msg>,
    mut client_rx: mpsc::Receiver<Msg>,
) where
    S: futures_util::Sink<Message> + Unpin + Send + 'static,
    S::Error: std::fmt::Debug,
{
    loop {
        tokio::select! {
            biased;
            res = rx.recv() => {
                match res {
                    Ok(msg) => {
                        debug!("Forwarding message to WebSocket: {msg:?}");
                        let msg_json = match msg.to_json() {
                            Ok(json) => json,
                            Err(e) => {
                                error!("Failed to serialize message to JSON: {e:?}");
                                continue;
                            }
                        };
                        if let Err(e) = ws_write.send(Message::Text(msg_json.into())).await {
                            error!("WebSocket send error: {e:?}");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            Some(msg) = client_rx.recv() => {
                let msg_json = match msg.to_json() {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Failed to serialize client message to JSON: {e:?}");
                        continue;
                    }
                };
                if let Err(e) = ws_write.send(Message::Text(msg_json.into())).await {
                    error!("WebSocket send error (client): {e:?}");
                    break;
                }
            }
        }
    }
}

async fn ws_receiver<S>(
    mut ws_read: S,
    tx_cmd_lb: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    tx_cmd_lw: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    client_tx: mpsc::Sender<Msg>,
) where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin
        + Send
        + 'static,
{
    while let Some(msg_res) = ws_read.next().await {
        match msg_res {
            Ok(Message::Text(text)) => {
                debug!("Received from client: {text}");

                let Ok(msg) = Msg::from_json(&text) else {
                    error!("Failed to parse message from WebSocket");
                    continue;
                };

                let target_tx = match msg.route_target() {
                    ServiceTarget::Lemonbeatd => &tx_cmd_lb,
                    ServiceTarget::Lwm2mserver => &tx_cmd_lw,
                    ServiceTarget::None => {
                        warn!("Could not determine target for message, not forwarding...");
                        continue;
                    }
                };

                let (reply_tx, reply_rx) = oneshot::channel();
                if let Err(e) = target_tx.send((msg, reply_tx)).await {
                    error!("Failed to forward message to service: {e:?}");
                    continue;
                }

                match reply_rx.await {
                    Ok(reply) => {
                        let _ = client_tx.send(reply).await;
                    }
                    Err(e) => {
                        error!("Failed to receive reply from service: {e:?}");
                    }
                }
            }
            Ok(Message::Close(frame)) => {
                debug!("Client closed connection: {frame:?}");
                break;
            }
            Ok(_) => {
                // Ignore non-text messages
            }
            Err(e) => {
                error!("WebSocket read error: {e:?}");
                break;
            }
        }
    }
}

async fn run_req_service(
    socket_path: &str,
    mut rx: mpsc::Receiver<(Msg, oneshot::Sender<Msg>)>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut req_service = tokio::select! {
        _ = shutdown.changed() => {
            debug!("Req service task not started for {socket_path}: shutdown requested");
            return;
        }
        res = sg_ipc::ReqService::new(socket_path) => {
            match res {
                Ok(service) => service,
                Err(e) => {
                    error!("Failed to create ReqService for {socket_path}: {e:?}");
                    return;
                }
            }
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                debug!("Req service task ending for {socket_path}: shutdown requested");
                return;
            }
            maybe = rx.recv() => {
                let Some((cmd_msg, reply_tx)) = maybe else {
                    debug!("Req service task ending for {socket_path}: command channel closed");
                    return;
                };

                debug!("Forwarding message to {socket_path}: {cmd_msg:?}");

                let request_id = cmd_msg.request_id.clone();

                let cmd_json = match cmd_msg.to_json() {
                    Ok(json) => json,
                    Err(e) => {
                        let err_msg = Msg::from_error_msg(format!("Failed to serialize command message: {e:?}").as_str());
                        let _ = reply_tx.send(err_msg);
                        continue;
                    }
                };

                let rep_msg = match req_service.send(cmd_json).await {
                    Ok(rep) => {
                        let mut msg = match Msg::from_json(&rep) {
                            Ok(m) => m,
                            Err(e) => {
                                error!("Failed to parse reply from service: {rep} with error: {e:?}");
                                continue;
                            },
                        };
                        msg.request_id = request_id;
                        msg
                    },
                    Err(e) => Msg::from_error_msg(format!("ReqService error: {e:?}").as_str())
                };
                let _ = reply_tx.send(rep_msg);
            }
        }
    }
}

async fn run_sub_service(
    socket_path: &str,
    tx_ws: broadcast::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
    service_name: &'static str,
) {
    let mut sub_service = sg_ipc::SubService::new(socket_path);

    tokio::select! {
        _ = shutdown.changed() => {
            debug!("IPC subservice ending for {socket_path}: shutdown requested");
        }
        res = sub_service.start(move |event_json: String| {
            let tx = tx_ws.clone();
            async move {
                if tx.receiver_count() > 0 {
                    let Ok(mut event_msg) = Msg::from_json(&event_json) else {
                        error!("Failed to parse event message from IPC: {event_json}");
                        return;
                    };
                    event_msg.metadata.get_or_insert_with(HashMap::new).insert(
                        "source".to_string(),
                        serde_json::Value::String(service_name.to_string()),
                    );
                    if let Err(e) = tx.send(event_msg) {
                        error!("Failed to forward event to WebSocket: {e:?}");
                    }
                }
            }
        }) => {
            if let Err(e) = res {
                error!("IPC subservice exited with error on {socket_path}: {e:?}");
            }
        }
    }
}

async fn run_ws_accept_loop(
    listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    tx_ws: broadcast::Sender<Msg>,
    tx_cmd_lb: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    tx_cmd_lw: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown requested; stopping WebSocket accept loop");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, addr)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let tx_ws = tx_ws.clone();
                        let tx_cmd_lb = tx_cmd_lb.clone();
                        let tx_cmd_lw = tx_cmd_lw.clone();

                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let callback = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                                    resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                                        let auth_header = req
                                            .headers()
                                            .get("authorization")
                                            .and_then(|h| h.to_str().ok());

                                        if !check_basic_auth(auth_header) {
                                            warn!(
                                                "WebSocket connection rejected: invalid credentials from {addr}"
                                            );
                                            let body = r#"{"error":"Authentication required","message":"Invalid or missing credentials"}"#;
                                            let response = Response::builder()
                                                .status(StatusCode::UNAUTHORIZED)
                                                .header("WWW-Authenticate", "Basic realm=\"WebSocket\"")
                                                .header("Content-Type", "application/json")
                                                .body(Some(body.to_string()))
                                                .unwrap();
                                            return Err(response);
                                        }

                                        Ok(resp)
                                    };

                                    match tokio_tungstenite::accept_hdr_async(tls_stream, callback).await {
                                        Ok(ws) => {
                                            debug!("New WebSocket connection established from {addr}");
                                            let (write, read) = ws.split();
                                            let rx = tx_ws.subscribe();
                                            let (client_tx, client_rx) = mpsc::channel::<Msg>(8);

                                            tokio::spawn(ws_sender(write, rx, client_rx));
                                            tokio::spawn(ws_receiver(
                                                read,
                                                tx_cmd_lb,
                                                tx_cmd_lw,
                                                client_tx,
                                            ));
                                        }
                                        Err(e) => {
                                            debug!("WebSocket handshake failed from {addr}: {e}");
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("TLS accept error: {e:?}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {e:?}");
                        return;
                    }
                }
            }
        }
    }
}

async fn wait_for_shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to register SIGTERM handler: {e:?}");
            tokio::signal::ctrl_c().await.ok();
            let _ = shutdown_tx.send(true);
            return;
        }
    };

    let sigterm_fut = async {
        let _ = sigterm.recv().await;
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down...");
        }
        _ = sigterm_fut => {
            info!("Received SIGTERM, shutting down...");
        }
    };

    let _ = shutdown_tx.send(true);
}

fn register_mdns_service() -> Result<mdns_sd::ServiceDaemon, anyhow::Error> {
    let mdns = mdns_sd::ServiceDaemon::new()?;
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let hostname_local = format!("{hostname}.local.");
    let local_ip = local_ip_address::local_ip()?.to_string();
    let service_type = "_gardena-smart._tcp.local.";
    let instance_name = format!("GARDENA smart Gateway {hostname}");

    let service = mdns_sd::ServiceInfo::new(
        service_type,
        &instance_name,
        &hostname_local,
        &local_ip,
        PORT,
        &[("path", "/"), ("tls", "true"), ("auth", "basic")][..],
    )?;

    mdns.register(service)?;
    info!("Registered mDNS service: {instance_name} at {hostname_local}:{PORT} ({local_ip})");

    Ok(mdns)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    gardenalog::init_tracing();

    PASSWORD
        .set(get_password())
        .expect("PASSWORD already initialized");

    let (tx_ws, _) = broadcast::channel::<Msg>(32);
    let (tx_cmd_lb, rx_cmd_lb) = mpsc::channel::<(Msg, oneshot::Sender<Msg>)>(32);
    let (tx_cmd_lw, rx_cmd_lw) = mpsc::channel::<(Msg, oneshot::Sender<Msg>)>(32);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut tasks = JoinSet::<()>::new();

    tasks.spawn(wait_for_shutdown_signal(shutdown_tx.clone()));

    tasks.spawn(run_req_service(
        LEMONBEATD_COMMAND_PATH,
        rx_cmd_lb,
        shutdown_rx.clone(),
    ));
    tasks.spawn(run_req_service(
        LWM2MSERVER_COMMAND_PATH,
        rx_cmd_lw,
        shutdown_rx.clone(),
    ));

    tasks.spawn(run_sub_service(
        LEMONBEATD_EVENT_PATH,
        tx_ws.clone(),
        shutdown_rx.clone(),
        "lemonbeatd",
    ));
    tasks.spawn(run_sub_service(
        LWM2MSERVER_EVENT_PATH,
        tx_ws.clone(),
        shutdown_rx.clone(),
        "lwm2mserver",
    ));

    let host = format!("0.0.0.0:{PORT}");
    let listener = tokio::net::TcpListener::bind(&host).await?;
    info!("WebSocket server listening on wss://{host}");

    let identity = load_tls_identity().await?;
    let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);

    tasks.spawn(run_ws_accept_loop(
        listener,
        tls_acceptor,
        tx_ws.clone(),
        tx_cmd_lb.clone(),
        tx_cmd_lw.clone(),
        shutdown_rx.clone(),
    ));

    let _mdns = match register_mdns_service() {
        Ok(daemon) => Some(daemon),
        Err(e) => {
            warn!("Failed to register mDNS service: {e:?}");
            None
        }
    };

    let mut shutdown_wait = shutdown_rx.clone();
    let _ = shutdown_wait.changed().await;
    info!("Shutting down");

    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            warn!("Background task ended with error: {e:?}");
        }
    }

    Ok(())
}
