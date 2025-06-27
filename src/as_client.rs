use reqwest::{Client, StatusCode};
use serde_json::json;
use crate::config::config::Config;
use url::Url;
use uuid::Uuid;

pub struct MatrixAsClient {
    homeserver: String,
    user_id: String,
    as_token: String,
    http: Client,
}

impl MatrixAsClient {
    pub fn new(config: &Config) -> Self {
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
        }
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

    pub async fn user_exists(&self) -> Option<bool> {
        let url = format!(
            "{}/_matrix/client/v3/profile/{}",
            self.homeserver, self.user_id
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

    pub async fn register_user(&self) {
        let url = format!("{}/_matrix/client/v3/register", self.homeserver);
        let localpart = self
            .user_id
            .split(':')
            .next()
            .unwrap()
            .trim_start_matches('@');
        let content = json!({
            "type": "m.login.application_service",
            "username": localpart,
        });
        let _ = self
            .http
            .post(url)
            .query(&[("access_token", self.as_token.clone())])
            .json(&content)
            .send()
            .await;
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
}
