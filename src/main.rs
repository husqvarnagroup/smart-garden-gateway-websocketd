use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
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
const CHANNEL_CAPACITY: usize = 32; // arbitrary value

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

enum DeviceService {
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
            metadata: Some(HashMap::from([(
                "error_source".to_string(),
                serde_json::Value::String("websocketd".to_string()),
            )])),
            payload: Some(HashMap::from([(
                "vs".to_string(),
                serde_json::Value::String(error.to_string()),
            )])),
            success: Some(false),
            ..Default::default()
        }
    }

    fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&vec![self])
    }

    fn device_service(&self) -> DeviceService {
        let Some(entity) = &self.entity else {
            error!("No entity field in message: {:?}", self);
            return DeviceService::None;
        };

        if let Some(service) = &entity.service {
            if service == "lemonbeatd" {
                return DeviceService::Lemonbeatd;
            } else if service == "lwm2mserver" {
                return DeviceService::Lwm2mserver;
            }
        }
        DeviceService::None
    }
}

async fn load_tls_identity() -> anyhow::Result<native_tls::Identity> {
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
        .with_context(|| format!("Failed to read certificate from {cert_path}"))?;
    let key = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("Failed to read key from {key_path}"))?;

    native_tls::Identity::from_pkcs8(&cert, &key).with_context(|| "Failed to create TLS identity")
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
    warn!("Failed to derive password from gateway ID, falling back to development password");
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
    mut ws: S,
    mut pub_rx: broadcast::Receiver<Msg>,
    mut rep_rx: mpsc::Receiver<Msg>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    S: futures_util::Sink<Message> + Unpin + Send + 'static,
    S::Error: std::fmt::Debug,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                debug!("WebSocket sender shutting down");
                break;
            }
            res = pub_rx.recv() => {
                match res {
                    Ok(msg) => {
                        debug!("Publishing to WebSocket: {msg:?}");
                        let msg_json = match msg.to_json() {
                            Ok(json) => json,
                            Err(e) => {
                                error!("Failed to serialize message to JSON: {e:?}");
                                continue;
                            }
                        };
                        if let Err(e) = ws.send(Message::Text(msg_json.into())).await {
                            error!("WebSocket send error: {e:?}");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        warn!("WebSocket receiver lagged behind, skipped {count} messages");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            Some(msg) = rep_rx.recv() => {
                debug!("Forwarding reply to WebSocket: {msg:?}");
                let msg_json = match msg.to_json() {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Failed to serialize client message to JSON: {e:?}");
                        continue;
                    }
                };
                if let Err(e) = ws.send(Message::Text(msg_json.into())).await {
                    error!("WebSocket send error: {e:?}");
                    break;
                }
            }
        }
    }
}

async fn ws_receiver<S>(
    mut ws: S,
    req_lb_tx: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    req_lw_tx: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    rep_tx: mpsc::Sender<Msg>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin
        + Send
        + 'static,
{
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("WebSocket receiver shutting down");
                break;
            }
            ws_msg = ws.next() => {
                let Some(ws_msg) = ws_msg else {
                    debug!("WebSocket stream ended");
                    break;
                };
                match ws_msg {
                    Ok(Message::Text(json)) => {
                        debug!("Received request from WebSocket: {json}");

                        let Ok(mut req_msg) = Msg::from_json(&json) else {
                            let err_msg = Msg::from_error_msg("Failed to parse JSON");
                            let _ = rep_tx.send(err_msg).await;
                            continue;
                        };

                        let req_tx = match req_msg.device_service() {
                            DeviceService::Lemonbeatd => &req_lb_tx,
                            DeviceService::Lwm2mserver => &req_lw_tx,
                            DeviceService::None => {
                                let err_msg = Msg::from_error_msg("Invalid entity.service provided");
                                let _ = rep_tx.send(err_msg).await;
                                continue;
                            }
                        };

                        // Device services (currently) do not expect entity.service for requests targeted at devices
                        if let Some(entity) = &mut req_msg.entity {
                            if entity.device.is_some() {
                                entity.service = None;
                            }
                        }

                        let (tx, rx) = oneshot::channel();
                        if let Err(e) = req_tx.send((req_msg, tx)).await {
                            error!("Failed to forward request to IPC: {e:?}");
                            let err_msg = Msg::from_error_msg("Internal error");
                            let _ = rep_tx.send(err_msg).await;
                            continue;
                        }

                        match rx.await {
                            Ok(rep) => {
                                let _ = rep_tx.send(rep).await;
                            }
                            Err(e) => {
                                error!("Failed to receive reply from IPC: {e:?}");
                                let err_msg = Msg::from_error_msg("Internal error");
                                let _ = rep_tx.send(err_msg).await;
                            }
                        }
                    }
                    Ok(Message::Close(frame)) => {
                        debug!("WebSocket connection closed: {frame:?}");
                        break;
                    }
                    Ok(_) => {
                        let err_msg = Msg::from_error_msg("Received non-text data");
                        let _ = rep_tx.send(err_msg).await;
                    }
                    Err(e) => {
                        error!("WebSocket read error: {e:?}");
                        break;
                    }
                }
            }
        }
    }
}

#[allow(clippy::similar_names)] // req_msg/rep_msg
async fn run_req_service(
    socket_path: &str,
    mut req_rx: mpsc::Receiver<(Msg, oneshot::Sender<Msg>)>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut req_service = tokio::select! {
        _ = shutdown_rx.changed() => {
            debug!("Task for {socket_path} not started: shutdown requested");
            return;
        }
        res = sg_ipc::ReqService::new(socket_path) => {
            match res {
                Ok(service) => service,
                Err(e) => {
                    error!("Failed to create IPC ReqService for {socket_path}: {e:?}");
                    return;
                }
            }
        }
    };

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("Stopping task for {socket_path}: shutdown requested");
                return;
            }
            maybe = req_rx.recv() => {
                let Some((req_msg, rep_tx)) = maybe else {
                    debug!("Stopping task for {socket_path}: command channel closed");
                    return;
                };

                debug!("Forwarding request to {socket_path}: {req_msg:?}");

                let request_id = req_msg.request_id.clone();

                let req_json = match req_msg.to_json() {
                    Ok(json) => json,
                    Err(e) => {
                        let err_msg = Msg::from_error_msg(format!("Failed to serialize request: {e:?}").as_str());
                        let _ = rep_tx.send(err_msg);
                        continue;
                    }
                };

                let rep_msg = match req_service.send(req_json.clone()).await {
                    Ok(json) => {
                        let mut msg = match Msg::from_json(&json) {
                            Ok(m) => m,
                            Err(e) => {
                                error!("Failed to parse reply: {json}, error: {e:?}");
                                let mut err_msg = Msg::from_error_msg(format!("Failed to parse reply: {e:?}").as_str());
                                err_msg.request_id = request_id.clone();
                                err_msg
                            },
                        };
                        msg.request_id = request_id;
                        debug!("Received reply from {socket_path}: {msg:?}");
                        msg
                    },
                    Err(e) => Msg::from_error_msg(format!("Failed to send request {req_json}, error: {e:?}").as_str())
                };
                if let Err(e) = rep_tx.send(rep_msg) {
                    debug!("Failed to send reply (connection likely closed): {e:?}");
                }
            }
        }
    }
}

async fn run_sub_service(
    socket_path: &str,
    pub_tx: broadcast::Sender<Msg>,
    mut shutdown_rx: watch::Receiver<bool>,
    service_name: &'static str,
) {
    let mut sub_service = sg_ipc::SubService::new(socket_path);

    tokio::select! {
        _ = shutdown_rx.changed() => {
            debug!("Stopping task for {socket_path}: shutdown requested");
        }
        res = sub_service.start(move |event_json: String| {
            let pub_tx = pub_tx.clone();
            async move {
                if pub_tx.receiver_count() > 0 {
                    let Ok(mut event_msg) = Msg::from_json(&event_json) else {
                        error!("Failed to parse event message from IPC: {event_json}");
                        return;
                    };
                    event_msg.metadata.get_or_insert_with(HashMap::new).insert(
                        "source".to_string(),
                        serde_json::Value::String(service_name.to_string()),
                    );
                    if let Err(e) = pub_tx.send(event_msg) {
                        error!("Failed to forward event to WebSocket: {e:?}");
                    }
                }
            }
        }) => {
            if let Err(e) = res {
                error!("IPC SubService for {socket_path} exited with error: {e:?}");
            }
        }
    }
}

async fn run_ws_accept_loop(
    listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    pub_tx: broadcast::Sender<Msg>,
    req_lb_tx: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    req_lw_tx: mpsc::Sender<(Msg, oneshot::Sender<Msg>)>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("Stopping task for WebSocket: shutdown requested");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, addr)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let pub_tx = pub_tx.clone();
                        let req_lb_tx = req_lb_tx.clone();
                        let req_lw_tx = req_lw_tx.clone();
                        let shutdown_rx = shutdown_rx.clone();

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
                                            let (ws_write, ws_read) = ws.split();
                                            let pub_rx = pub_tx.subscribe();
                                            let (rep_tx, rep_rx) = mpsc::channel::<Msg>(CHANNEL_CAPACITY);
                                            let shutdown_rx = shutdown_rx.clone();

                                            tokio::spawn(ws_sender(ws_write, pub_rx, rep_rx, shutdown_rx.clone()));
                                            tokio::spawn(ws_receiver(
                                                ws_read,
                                                req_lb_tx,
                                                req_lw_tx,
                                                rep_tx,
                                                shutdown_rx,
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
        Ok(()) = tokio::signal::ctrl_c() => {
            debug!("Received SIGINT");
        }
        () = sigterm_fut => {
            debug!("Received SIGTERM");
        }
    };

    let _ = shutdown_tx.send(true);
}

fn register_mdns_service() -> anyhow::Result<mdns_sd::ServiceDaemon> {
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
async fn main() -> anyhow::Result<()> {
    gardenalog::init_tracing();

    PASSWORD
        .set(get_password())
        .expect("PASSWORD already initialized");

    let (pub_tx, _) = broadcast::channel::<Msg>(CHANNEL_CAPACITY);
    let (req_lb_tx, req_lb_rx) = mpsc::channel::<(Msg, oneshot::Sender<Msg>)>(CHANNEL_CAPACITY);
    let (req_lw_tx, req_lw_rx) = mpsc::channel::<(Msg, oneshot::Sender<Msg>)>(CHANNEL_CAPACITY);

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let mut tasks = JoinSet::<()>::new();

    tasks.spawn(wait_for_shutdown_signal(shutdown_tx.clone()));

    tasks.spawn(run_req_service(
        LEMONBEATD_COMMAND_PATH,
        req_lb_rx,
        shutdown_rx.clone(),
    ));
    tasks.spawn(run_req_service(
        LWM2MSERVER_COMMAND_PATH,
        req_lw_rx,
        shutdown_rx.clone(),
    ));

    tasks.spawn(run_sub_service(
        LEMONBEATD_EVENT_PATH,
        pub_tx.clone(),
        shutdown_rx.clone(),
        "lemonbeatd",
    ));
    tasks.spawn(run_sub_service(
        LWM2MSERVER_EVENT_PATH,
        pub_tx.clone(),
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
        pub_tx.clone(),
        req_lb_tx.clone(),
        req_lw_tx.clone(),
        shutdown_rx.clone(),
    ));

    let mdns = match register_mdns_service() {
        Ok(daemon) => Some(daemon),
        Err(e) => {
            warn!("Failed to register mDNS service: {e:?}");
            None
        }
    };

    let _ = shutdown_rx.changed().await;
    info!("Shutting down...");

    if let Some(daemon) = mdns {
        if let Err(e) = daemon.shutdown() {
            warn!("Failed to shutdown mDNS service: {e:?}");
        } else {
            debug!("mDNS service unregistered");
        }
    }

    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            warn!("Background task ended with error: {e:?}");
        }
    }

    Ok(())
}
