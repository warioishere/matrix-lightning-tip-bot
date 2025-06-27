use reqwest::{Client, StatusCode};
use serde_json::json;
use crate::config::config::Config;
use crate::data_layer::data_layer::DataLayer;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use urlencoding::encode;

#[derive(Clone)]
pub struct MatrixAsClient {
    homeserver: String,
    user_id: String,
    as_token: String,
    http: Client,
    dm_rooms: Arc<Mutex<HashMap<String, String>>>,
    data_layer: DataLayer,
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
        }
    }

    pub async fn set_presence(&self, presence: &str, status_msg: &str) {
        let url = format!(
            "{}/_matrix/client/v3/presence/{}/status",
            self.homeserver, self.user_id
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
            ("user_id", self.user_id.clone()),
            ("access_token", self.as_token.clone()),
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
}
