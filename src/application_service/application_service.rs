use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use reqwest::{Client, ClientBuilder};
use std::sync::Mutex;
use ruma::api::client::sync::sync_events::DeviceLists;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection};
use crate::application_service::registration::Registration;
use crate::application_service::txnid::TransactionIDCache;
use ruma::api::appservice::query::query_user_id::v1::Request as QueryUserIdRequest;

type Event = String;

pub struct ApplicationServiceState {
    pub clients: HashMap<Arc<ruma::UserId>, Client>,  // Wrap UserId in Arc
    pub intents: HashMap<Arc<ruma::UserId>, String>,   // Wrap UserId in Arc
    pub registration: Registration,
    pub http_client: Client,
    pub event_channel: mpsc::Sender<Event>,
    pub to_device_events: mpsc::Sender<Event>,
    pub txn_idc_cache: TransactionIDCache,
    // otk_counts: mpsc::Sender<OTKCount>, not supported
    pub device_lists: mpsc::Sender<DeviceLists>,
    pub user_agent: String,
    pub live: bool,
    pub ready: bool,
}

impl ApplicationServiceState {
    async fn new(create_opts: CreateOpts) -> Self {
        // Simple HTTP client for outgoing requests
        let http_client = ClientBuilder::new()
            .timeout(Duration::from_secs(180))
            .build()
            .expect("Failed to create HTTP client");

        // Create channels
        let (event_tx, _event_rx) = mpsc::channel::<Event>(128);
        let (to_device_tx, _to_device_rx) = mpsc::channel::<Event>(128);
        //let (otk_counts_tx, _otk_counts_rx) = mpsc::channel::<OTKCount>(64);
        let (device_lists_tx, _device_lists_rx) = mpsc::channel::<DeviceLists>(128);

        // Initialize state
        ApplicationServiceState {
            clients: HashMap::new(),
            intents: HashMap::new(),
            registration: create_opts.registration,
            http_client,
            event_channel: event_tx,
            to_device_events: to_device_tx,
            txn_idc_cache: TransactionIDCache::new(128),
            //otk_counts: otk_counts_tx,
            device_lists: device_lists_tx,
            user_agent: "mautrix".to_string(),
            live: true,
            ready: false,
        }
    }
}

// // RumaHandler trait with associated types
// pub trait FilterExtender {
//
//     fn add_to_filter(
//         self,
//         filter: warp::filters::BoxedFilter<(impl warp::Reply,)>,
//         state: Arc<Mutex<ApplicationServiceState>>,
//     ) -> warp::filters::BoxedFilter<(impl warp::Reply,)>;
// }



#[derive(Debug, Serialize, Deserialize)]
pub struct HostConfig {
    #[serde(rename = "hostname")]
    pub hostname: String,

    #[serde(rename = "port")]
    pub port: Option<u16>, // Port is optional if using a Unix socket
}

pub struct CreateOpts {
    // Required fields
    registration: Registration, // Using Arc to represent a shared Registration instance
    homeserver_domain: String,
    homeserver_url: String,
    host_config: HostConfig,
}

use crate::matrix_bot::MatrixBot;

#[derive(Deserialize)]
struct TransactionRequest {
    /// Timeline events for this transaction
    pub events: Vec<serde_json::Value>,
    /// Ephemeral events (ignored)
    #[serde(default)]
    pub ephemeral: Vec<serde_json::Value>,
    /// To-device messages (ignored)
    #[serde(default, rename = "de.sorunome.msc2409.to_device")]
    pub to_device: Vec<serde_json::Value>,
}

async fn transactions_handler(
    txn_id: String,
    query: std::collections::HashMap<String, String>,
    req: TransactionRequest,
    authorization: Option<String>,
    state: Arc<Mutex<ApplicationServiceState>>,
    bot: Arc<MatrixBot>,
    server_token: String,
) -> Result<impl warp::Reply, Rejection> {
    use warp::http::StatusCode;

    let auth_header = authorization.as_deref();
    if let Some(header) = auth_header {
        if header != format!("Bearer {}", server_token) {
            return Ok(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "errcode": "M_FORBIDDEN",
                    "error": "Invalid application service token",
                })),
                StatusCode::FORBIDDEN,
            ));
        }
        if let Some(q) = query.get("access_token") {
            if q != &server_token {
                return Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "errcode": "M_FORBIDDEN",
                        "error": "Invalid application service token",
                    })),
                    StatusCode::FORBIDDEN,
                ));
            }
        }
    } else if query.get("access_token") != Some(&server_token) {
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "errcode": "M_FORBIDDEN",
                "error": "Invalid application service token",
            })),
            StatusCode::FORBIDDEN,
        ));
    }

    {
        let mut state_guard = state.lock().unwrap();
        if state_guard.txn_idc_cache.is_processed(&txn_id) {
            return Ok(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({})),
                StatusCode::OK,
            ));
        }
        state_guard.txn_idc_cache.mark_processed(txn_id);
    }

    bot.handle_transaction_events(req.events).await;
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({})),
        StatusCode::OK,
    ))
}

pub async fn run_server(bot: Arc<MatrixBot>, registration: Registration) {
    // Derive host and port from the registration URL
    let url = url::Url::parse(&registration.url).expect("Invalid registration URL");
    let port = url.port().unwrap_or(9000);

    let create_opts = CreateOpts {
        registration: registration.clone(),
        homeserver_domain: String::new(),
        homeserver_url: String::new(),
        host_config: HostConfig { hostname: "0.0.0.0".to_owned(), port: Some(port) },
    };

    let state = Arc::new(Mutex::new(ApplicationServiceState::new(create_opts).await));

    let health_state = state.clone();
    let health = warp::path("_matrix")
        .and(warp::path("app"))
        .and(warp::path("v1"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(warp::any().map(move || health_state.clone()))
        .map(|_: Arc<Mutex<ApplicationServiceState>>| warp::reply::json(&"OK"));

    let query_state = state.clone();

    let query_user = warp::path("_matrix")
        .and(warp::path("app"))
        .and(warp::path("v1"))
        .and(warp::path("users"))
        .and(warp::path::param::<String>())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::path::end())
        .and(warp::any().map(move || query_state.clone()))
        .and_then(
            |user: String,
             _query: std::collections::HashMap<String, String>,
             state: Arc<Mutex<ApplicationServiceState>>| async move {
                use crate::application_service::http_methods::query_user_id_handler;
                use crate::application_service::http_methods::QueryUserIdResponse;
                use ruma::OwnedUserId;
                use warp::http::StatusCode;

                let user_id: OwnedUserId = user.parse().map_err(|_| warp::reject())?;
                let req = QueryUserIdRequest::new(user_id);
                match query_user_id_handler(state, req).await {
                    Ok(QueryUserIdResponse { exists }) => {
                        Ok::<_, Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({ "exists": exists })),
                            StatusCode::OK,
                        ))
                    }
                    Err(err) => Err(err),
                }
            },
        );

    let bot_filter = warp::any().map(move || bot.clone());
    let state_filter = warp::any().map(move || state.clone());

    let server_token = registration.server_token.clone();
    let transactions_route = warp::path("_matrix")
        .and(warp::path("app"))
        .and(warp::path("v1"))
        .and(warp::path("transactions"))
        .and(warp::path::param::<String>())
        .and(warp::put())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::body::json())
        .and(warp::header::optional::<String>("authorization"))
        .and(state_filter)
        .and(bot_filter.clone())
        .and(warp::any().map(move || server_token.clone()))
        .and_then(transactions_handler);

    let routes = health.or(query_user).or(transactions_route);

    let addr = ([0, 0, 0, 0], port);
    warp::serve(routes).run(addr).await;
}
