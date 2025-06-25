use warp::Rejection;
use std::sync::{Arc, Mutex};
use crate::application_service::application_service::ApplicationServiceState;
use crate::application_service::registration::NamespaceList;
use ruma::api::appservice::query::query_user_id::v1::Request as QueryUserIdRequest;
use regex::Regex;

#[derive(serde::Serialize)]
pub struct QueryUserIdResponse {
    pub exists: bool,
}

pub async fn query_user_id_handler(
    state: Arc<Mutex<ApplicationServiceState>>,
    req: QueryUserIdRequest,
) -> Result<QueryUserIdResponse, Rejection> {
    let user_id = req.user_id;

    let namespaces: Option<NamespaceList> = {
        let state_guard = state.lock().unwrap();
        state_guard.registration.namespaces.user_ids.clone()
    };

    let mut exists = false;

    if let Some(ns_list) = namespaces {
        for ns in ns_list {
            if let Ok(re) = Regex::new(&ns.regex) {
                if re.is_match(user_id.as_str()) {
                    exists = true;
                    break;
                }
            }
        }
    }

    Ok(QueryUserIdResponse { exists })
}
