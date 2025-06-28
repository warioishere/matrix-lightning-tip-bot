use reqwest::{Client, StatusCode};
use serde_json::json;
use ruma::api::client::keys::{claim_keys, get_keys, upload_keys};
use ruma::api::IncomingResponse;
use crate::config::config::Config;
use crate::data_layer::data_layer::DataLayer;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use urlencoding::encode;

pub const DEVICE_ID: &str = "ASDEVICE";

#[derive(Clone)]
pub struct MatrixAsClient {
    homeserver: String,
    user_id: String,
    as_token: String,
    access_token: Option<String>,
    http: Client,
    dm_rooms: Arc<Mutex<HashMap<String, String>>>,
    data_layer: DataLayer,
    #[allow(dead_code)]
    device_id: String,
}

impl MatrixAsClient {
    pub fn new(config: &Config, data_layer: DataLayer) -> Self {
        Self {
            homeserver: config.matrix_server.clone(),
            user_id: format!(
                "@{}:{}",
                config.registration.sender_localpart,
                Url::parse(&config.matrix_server)
                    .unwrap()
                    .host_str()
                    .unwrap(),
            ),
            as_token: config.registration.app_token.clone(),
            access_token: None,
            http: Client::new(),
            dm_rooms: Arc::new(Mutex::new(HashMap::new())),
            data_layer,
            device_id: DEVICE_ID.to_owned(),
        }
    }

    pub fn load_auth(&mut self) {
        if let Some(record) = self.data_layer.load_client_auth() {
            self.access_token = Some(record.access_token);
            self.device_id = record.device_id;
        }
    }

    pub fn has_access_token(&self) -> bool {
        self.access_token.is_some()
    }

    async fn save_auth(&self) {
        if let Some(token) = &self.access_token {
            self.data_layer
                .save_client_auth(token, &self.device_id);
        }
    }

    pub async fn login(&mut self) {
        let localpart = self
            .user_id
            .split(':')
            .next()
            .unwrap()
            .trim_start_matches('@');
        let url = format!(
            "{}/_matrix/client/v3/login?access_token={}",
            self.homeserver, self.as_token
        );
        let body = json!({
            "type": "m.login.application_service",
            "identifier": { "type": "m.id.user", "user": localpart },
            "device_id": self.device_id,
            "initial_device_display_name": "Lightning Tip Bot"
        });
        if let Ok(resp) = self.http.post(url).json(&body).send().await {
            if resp.status() == StatusCode::OK {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(access) = json.get("access_token").and_then(|v| v.as_str()) {
                        self.access_token = Some(access.to_owned());
                    }
                    if let Some(dev) = json.get("device_id").and_then(|v| v.as_str()) {
                        self.device_id = dev.to_owned();
                    }
                    self.save_auth().await;
                }
            }
        }
    }

    pub async fn set_presence(&self, presence: &str, status_msg: &str) {
        let url = format!(
            "{}/_matrix/client/v3/presence/{}/status",
            self.homeserver,
            encode(&self.user_id)
        );
        let content = json!({
            "presence": presence,
            "status_msg": status_msg,
        });
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn set_avatar_url(&self, mxc_url: &str) {
        let url = format!(
            "{}/_matrix/client/v3/profile/{}/avatar_url",
            self.homeserver, encode(&self.user_id)
        );
        let content = json!({ "avatar_url": mxc_url });
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn accept_invite(&self, room_id: &str) {
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/state/m.room.member/{}",
            self.homeserver, room_id, encode(&self.user_id)
        );
        let content = json!({ "membership": "join" });
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    fn auth_query(&self) -> Vec<(&str, String)> {
        vec![
            ("access_token", self.access_token.clone().unwrap_or_default()),
            ("device_id", self.device_id.clone()),
        ]
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }


    pub async fn send_text(&self, room_id: &str, body: &str) {
        let txn = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver, room_id, txn
        );
        let content = json!({"msgtype": "m.text", "body": body});
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn send_formatted(&self, room_id: &str, body: &str, formatted: &str) {
        let txn = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver, room_id, txn
        );
        let content = json!({
            "msgtype": "m.text",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted
        });
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn upload(&self, data: &[u8], content_type: &str, filename: &str) -> Option<String> {
        let url = format!("{}/_matrix/media/v3/upload", self.homeserver);
        self.http
            .post(url)
            .query(&self.auth_query())
            .query(&[("filename", filename.to_owned())])
            .header("Content-Type", content_type)
            .body(data.to_owned())
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()?
            .get("content_uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
    }

    pub async fn send_image(&self, room_id: &str, filename: &str, mxc_url: &str) {
        let txn = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver, room_id, txn
        );
        let content = json!({
            "msgtype": "m.image",
            "body": filename,
            "url": mxc_url,
        });
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn send_raw(&self, room_id: &str, event_type: &str, content: serde_json::Value) {
        let txn = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/{}/{}",
            self.homeserver, room_id, event_type, txn
        );
        let _ = self
            .http
            .put(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn room_is_encrypted(&self, room_id: &str) -> Option<bool> {
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/state/m.room.encryption",
            self.homeserver, room_id
        );
        match self
            .http
            .get(url)
            .query(&self.auth_query())
            .send()
            .await
        {
            Ok(resp) => match resp.status() {
                StatusCode::OK => Some(true),
                StatusCode::NOT_FOUND => Some(false),
                _ => None,
            },
            Err(_) => None,
        }
    }

    pub async fn get_event(&self, room_id: &str, event_id: &str) -> Option<serde_json::Value> {
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/event/{}",
            self.homeserver, room_id, event_id
        );
        match self
            .http
            .get(url)
            .query(&self.auth_query())
            .send()
            .await
        {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(json) => Some(json),
                Err(_) => None,
            },
            Err(_) => None,
        }
    }

    async fn send_request(
        &self,
        request: ruma::exports::http::Request<Vec<u8>>,
    ) -> Option<ruma::exports::http::Response<Vec<u8>>> {
        use reqwest::header::{HeaderName, HeaderValue};
        use reqwest::Method;

        let method = Method::from_bytes(request.method().as_str().as_bytes()).ok()?;
        let url = request.uri().to_string();
        let mut builder = self.http.request(method, url);
        for (name, value) in request.headers().iter() {
            let hname = HeaderName::from_bytes(name.as_str().as_bytes()).ok()?;
            let hvalue = HeaderValue::from_bytes(value.as_bytes()).ok()?;
            builder = builder.header(hname, hvalue);
        }
        let resp = builder.body(request.body().clone()).send().await.ok()?;
        let status = resp.status();
        let status_code = ruma::exports::http::StatusCode::from_u16(status.as_u16()).ok()?;
        let mut resp_builder = ruma::exports::http::Response::builder().status(status_code);
        for (name, value) in resp.headers() {
            let hname = ruma::exports::http::header::HeaderName::from_bytes(name.as_str().as_bytes()).ok()?;
            let hvalue = ruma::exports::http::header::HeaderValue::from_bytes(value.as_bytes()).ok()?;
            resp_builder = resp_builder.header(hname, hvalue);
        }
        let bytes = resp.bytes().await.ok()?;
        resp_builder.body(bytes.to_vec()).ok()
    }

    async fn create_dm_room(&self, user_id: &str) -> Option<String> {
        {
            let map = self.dm_rooms.lock().await;
            if let Some(room) = map.get(user_id) {
                return Some(room.clone());
            }
        }

        if let Some(room) = self.data_layer.dm_room_for_user(user_id) {
            let mut map = self.dm_rooms.lock().await;
            map.insert(user_id.to_owned(), room.clone());
            return Some(room);
        }

        let url = format!("{}/_matrix/client/v3/createRoom", self.homeserver);
        let content = json!({
            "invite": [user_id],
            "is_direct": true
        });
        let room_id = self
            .http
            .post(url)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()?
            .get("room_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());

        if let Some(ref id) = room_id {
            let mut map = self.dm_rooms.lock().await;
            map.insert(user_id.to_owned(), id.clone());
            self.data_layer.save_dm_room(user_id, id);
        }

        room_id
    }

    pub async fn send_dm(&self, user_id: &str, body: &str) {
        if let Some(room_id) = self.create_dm_room(user_id).await {
            self.send_text(&room_id, body).await;
        }
    }

    pub async fn keys_upload(
        &self,
        request: upload_keys::v3::Request,
    ) -> Option<upload_keys::v3::Response> {
        use ruma::api::{OutgoingRequest, SendAccessToken, MatrixVersion};
        let token = self.access_token.as_deref()?;
        let http_req = request
            .try_into_http_request::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::IfRequired(token),
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        upload_keys::v3::Response::try_from_http_response(response).ok()
    }

    pub async fn keys_query(
        &self,
        request: get_keys::v3::Request,
    ) -> Option<get_keys::v3::Response> {
        use ruma::api::{OutgoingRequest, SendAccessToken, MatrixVersion};
        let token = self.access_token.as_deref()?;
        let http_req = request
            .try_into_http_request::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::IfRequired(token),
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        get_keys::v3::Response::try_from_http_response(response).ok()
    }

    pub async fn keys_claim(
        &self,
        request: claim_keys::v3::Request,
    ) -> Option<claim_keys::v3::Response> {
        use ruma::api::{OutgoingRequest, SendAccessToken, MatrixVersion};
        let token = self.access_token.as_deref()?;
        let http_req = request
            .try_into_http_request::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::IfRequired(token),
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        claim_keys::v3::Response::try_from_http_response(response).ok()
    }
}
