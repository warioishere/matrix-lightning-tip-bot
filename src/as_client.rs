use reqwest::{Client, StatusCode};
use ruma::api::IncomingResponse;
use serde_json::json;
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
            http: Client::new(),
            dm_rooms: Arc::new(Mutex::new(HashMap::new())),
            data_layer,
            device_id: DEVICE_ID.to_owned(),
        }
    }

    fn ensure_device_params(url: &mut url::Url, device_id: &str) {
        let has_device_id = url.query_pairs().any(|(k, _)| k == "device_id");
        let has_msc = url
            .query_pairs()
            .any(|(k, _)| k == "org.matrix.msc3202.device_id");
        {
            let mut qp = url.query_pairs_mut();
            if !has_device_id {
                qp.append_pair("device_id", device_id);
            }
            if !has_msc {
                qp.append_pair("org.matrix.msc3202.device_id", device_id);
            }
        }
    }

    pub async fn create_device_msc4190(&self) -> Result<(), reqwest::Error> {
        let url = format!("{}/_matrix/client/v3/devices/{}", self.homeserver, DEVICE_ID);
        let body = serde_json::json!({
            "display_name": "Lightning Tip Bot"
        });
        let resp = self
            .http
            .put(url)
            .bearer_auth(&self.as_token)
            .query(&[("user_id", self.user_id.clone())])
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            log::warn!("create_device_msc4190 failed: {} - {}", status.as_u16(), text);
        }
        Ok(())
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    fn auth_query(&self) -> Vec<(&str, String)> {
        vec![
            ("user_id", self.user_id.clone()),
            ("device_id", self.device_id.clone()),
            ("org.matrix.msc3202.device_id", self.device_id.clone()),
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
            .query(&self.auth_query())
            .json(&content)
            .send()
            .await;
    }

    pub async fn upload(&self, data: &[u8], content_type: &str, filename: &str) -> Option<String> {
        let url = format!("{}/_matrix/media/v3/upload", self.homeserver);
        self.http
            .post(url)
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
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
            .bearer_auth(&self.as_token)
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
        let mut url: url::Url = request.uri().to_string().parse().ok()?;
        Self::ensure_device_params(&mut url, &self.device_id);

        let mut builder = self.http.request(method, url.to_string());
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
            .bearer_auth(&self.as_token)
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
        request: ruma::api::client::keys::upload_keys::v3::Request,
    ) -> Option<(ruma::exports::http::Response<Vec<u8>>, ruma::exports::http::StatusCode)> {
        use ruma::api::{MatrixVersion, SendAccessToken, OutgoingRequestAppserviceExt};
        use ruma::OwnedUserId;

        let user_id: OwnedUserId = self.user_id.parse().ok()?;
        let http_req = request
            .try_into_http_request_with_user_id::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::Appservice(&self.as_token),
                &user_id,
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        let status = response.status();
        Some((response, status))
    }

    pub async fn keys_query(
        &self,
        request: ruma::api::client::keys::get_keys::v3::Request,
    ) -> Option<(ruma::api::client::keys::get_keys::v3::Response, ruma::exports::http::StatusCode)> {
        use ruma::api::{MatrixVersion, SendAccessToken, OutgoingRequestAppserviceExt};
        use ruma::OwnedUserId;

        let user_id: OwnedUserId = self.user_id.parse().ok()?;
        let http_req = request
            .try_into_http_request_with_user_id::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::Appservice(&self.as_token),
                &user_id,
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        let status = response.status();
        let parsed = ruma::api::client::keys::get_keys::v3::Response::try_from_http_response(response).ok()?;
        Some((parsed, status))
    }

    pub async fn keys_claim(
        &self,
        request: ruma::api::client::keys::claim_keys::v3::Request,
    ) -> Option<(ruma::api::client::keys::claim_keys::v3::Response, ruma::exports::http::StatusCode)> {
        use ruma::api::{MatrixVersion, SendAccessToken, OutgoingRequestAppserviceExt};
        use ruma::OwnedUserId;

        let user_id: OwnedUserId = self.user_id.parse().ok()?;
        let http_req = request
            .try_into_http_request_with_user_id::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::Appservice(&self.as_token),
                &user_id,
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        let status = response.status();
        let parsed = ruma::api::client::keys::claim_keys::v3::Response::try_from_http_response(response).ok()?;
        Some((parsed, status))
    }

    pub async fn send_to_device(
        &self,
        request: matrix_sdk_crypto::types::requests::ToDeviceRequest,
    ) -> Option<ruma::api::client::to_device::send_event_to_device::v3::Response> {
        use ruma::api::{MatrixVersion, SendAccessToken, OutgoingRequestAppserviceExt};
        use ruma::OwnedUserId;

        let user_id: OwnedUserId = self.user_id.parse().ok()?;
        let req = ruma::api::client::to_device::send_event_to_device::v3::Request::new_raw(
            request.event_type,
            request.txn_id,
            request.messages,
        );
        let http_req = req
            .try_into_http_request_with_user_id::<Vec<u8>>(
                &self.homeserver,
                SendAccessToken::Appservice(&self.as_token),
                &user_id,
                &[MatrixVersion::V1_1],
            )
            .ok()?;
        let response = self.send_request(http_req).await?;
        ruma::api::client::to_device::send_event_to_device::v3::Response::try_from_http_response(response).ok()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_device_params_no_duplicate() {
        let mut url = url::Url::parse(
            "https://example.com/_matrix/client/v3/path?device_id=ASDEVICE&org.matrix.msc3202.device_id=ASDEVICE",
        )
        .unwrap();
        MatrixAsClient::ensure_device_params(&mut url, DEVICE_ID);

        let count_device = url.query_pairs().filter(|(k, _)| k == "device_id").count();
        let count_msc = url
            .query_pairs()
            .filter(|(k, _)| k == "org.matrix.msc3202.device_id")
            .count();
        assert_eq!(count_device, 1);
        assert_eq!(count_msc, 1);
    }
}
