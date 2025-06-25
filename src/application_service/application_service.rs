use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use reqwest::cookie::Jar;
use reqwest::{Client, ClientBuilder};
use std::sync::Mutex;
use http::{HeaderMap, Method};
use ruma::api::client::sync::sync_events::DeviceLists;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection};
use crate::application_service::registration::Registration;
use crate::application_service::txnid::TransactionIDCache;
use ruma::api::{
    IncomingRequest,
};
use std::future::Future;
use std::pin::Pin;
use serde_json::{
    from_slice as from_json_slice, Value as JsonValue,
};
use ruma::api::OutgoingResponse;
use http::Request;

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
        // Configure the HTTP client with a cookie jar
        let jar = Arc::new(Jar::default());
        let http_client = ClientBuilder::new()
            .cookie_provider(jar.clone())
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


// Helper function to convert HTTP method to Warp filter
fn method_to_filter(method: &Method) -> warp::filters::BoxedFilter<()> {
    match method {
        &Method::GET => warp::get().boxed(),
        &Method::POST => warp::post().boxed(),
        &Method::PUT => warp::put().boxed(),
        &Method::DELETE => warp::delete().boxed(),
        _ => panic!("Unsupported HTTP method: {:?}", method),
    }
}

// impl<Req, E, F, Fut> FilterExtender for F
// where
//     Req: IncomingRequest + Send + 'static,
//     F: Fn(Arc<Mutex<ApplicationServiceState>>, Req) -> Fut + Clone  + Send + 'static,
//     Fut: Future<Output = Result<Req::OutgoingResponse, E>> + Send,
//     E: warp::reject::Reject + Send + 'static,
// {
//
//     fn add_to_filter(self,
//                      filter: warp::filters::BoxedFilter<(impl warp::Reply,)>,
//                      state: Arc<Mutex<ApplicationServiceState>>) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
//
//         let meta = <Req as IncomingRequest>::METADATA;
//         let mut combined_filter = filter;
//
//         for path in meta.history.all_paths() {
//             let handler = self.clone();
//             let state = state.clone();
//             let method_filter = method_to_filter(&meta.method);
//
//             let endpoint =
//                 warp::path(path).and(method_filter)
//                                 .and(warp::any().map(move || state.clone()))
//                                 .and_then(move |state, req| async move {
//                                     handler(state, req).await
//                                                        .map(|response| warp::reply::json(&response))
//                                                        .map_err(warp::reject::custom)
//                                 }).boxed();
//
//             combined_filter = combined_filter.or(endpoint)
//                                              .unify()
//                                              .boxed();
//         }
//
//         combined_filter
//     }
// }



// macro_rules! impl_ruma_handler {
//     ( $($ty:ident),* $(,)? ) => {
//
//     }
// }

// Apply the macro
//impl_ruma_handler!();

// Invoke the macro
// impl_ruma_handler!(T1);
// impl_ruma_handler!(T1, T2);
// impl_ruma_handler!(T1, T2, T3);
// impl_ruma_handler!(T1, T2, T3, T4);
// impl_ruma_handler!(T1, T2, T3, T4, T5);
// impl_ruma_handler!(T1, T2, T3, T4, T5, T6);
// impl_ruma_handler!(T1, T2, T3, T4, T5, T6, T7);
// impl_ruma_handler!(T1, T2, T3, T4, T5, T6, T7, T8);

// Build the router with Warp filters
use ruma::api::appservice::query::query_user_id::v1::{Request as QueryUserIdRequest, Response as QueryUserIdResponse};
use warp::path::FullPath;

type QueryUserIdHandler = fn(
    Arc<Mutex<ApplicationServiceState>>,
    QueryUserIdRequest,
) -> Pin<Box<dyn Future<Output = Result<QueryUserIdResponse, Rejection>> + Send>>;

pub fn create_user_id_filter(
    state: Arc<Mutex<ApplicationServiceState>>,
    handler: QueryUserIdHandler,
) {
    let meta = QueryUserIdRequest::METADATA;

    for path in meta.history.all_paths() {
        let state = state.clone();
        let method_filter = method_to_filter(&meta.method);

        let endpoint = warp::path(path)
            .and(method_filter)
            .and(warp::any().map(move || state.clone())) // Provide `state`
            .and(warp::header::headers_cloned()) // Extract headers
            .and(warp::body::bytes()) // Extract the raw body as `Bytes`
            .and(warp::method()) // Extract the HTTP method
            .and(warp::path::full()) // Extract the full path
            .and_then(move |state, headers: HeaderMap, body, method, path: FullPath| async move {
                // Build the `http::Request` manually
                let uri = format!("{}", path.as_str());
                let mut request = Request::builder()
                    .method(method)
                    .uri(uri);

                for header in headers {
                    let name = header.0.unwrap().as_str();
                    let value = header.1.to_str().unwrap();
                    request = request.header(name, value);
                }

                // Set the body
                let request = request.body(body).map_err(warp::reject::custom)?;

                // Convert the request using `try_from_http_request`
                match QueryUserIdRequest::try_from_http_request(request) {
                    Ok(req) => {
                        // Pass the `state` and parsed `req` to the handler
                        match handler(state, req).await {
                            Ok(response) => {
                                let response = response.try_into_http_response::<Vec<u8>>().unwrap();
                                let json_body: JsonValue = from_json_slice(response.body()).unwrap();
                                Ok::<_, Rejection>(warp::reply::json(&json_body))
                            }
                            Err(err) => Err(err),
                        }
                    }
                    Err(err) => Err(warp::reject::custom(err)), // Handle conversion error
                }
            });
    }
}

pub fn build_router(
    state: Arc<Mutex<ApplicationServiceState>>,
) -> impl Filter + Clone {
    // Starting with a base filter (e.g., a health check)

    // Starting with a base filter (e.g., a health check)
    let base_filter = warp::path!("health")
        .and(warp::any().map(move || state.clone()))
        .map(|state: Arc<Mutex<ApplicationServiceState>>| {
            // Example health check with access to state
            // let _ = state.lock().unwrap(); // Just to demonstrate state usage
            warp::reply::json(&"OK")
        });

    base_filter
}

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
