use crate::config::config::Config;
use crate::data_layer::data_layer::DataLayer;
use crate::lnbits_client::lnbits_client::LNBitsClient;
mod commands;
mod business_logic;
mod utils;
pub use crate::data_layer::data_layer::LNBitsId;
use self::business_logic::BusinessLogicContext;
use self::commands::Command;
use crate::as_client::MatrixAsClient;
use crate::encryption::EncryptionHelper;
use serde_json::Value;
use simple_error::{SimpleError, bail};
use std::collections::HashMap;
use url::Url;
use tokio::sync::Mutex;

pub struct MatrixBot {
    pub business_logic_context: BusinessLogicContext,
    as_client: MatrixAsClient,
    encryption: EncryptionHelper,
    room_encryption: Mutex<HashMap<String, bool>>,
}

impl MatrixBot {
    pub async fn new(data_layer: DataLayer, lnbits_client: LNBitsClient, config: &Config) -> Self {
        let ctx = BusinessLogicContext::new(lnbits_client, data_layer.clone(), config);
        let as_client = MatrixAsClient::new(config);
        let encryption = EncryptionHelper::new(&data_layer, config).await;
        MatrixBot {
            business_logic_context: ctx,
            as_client,
            encryption,
            room_encryption: Mutex::new(HashMap::new()),
        }
    }

    pub async fn init(&self) {
        let user_id = self.as_client.user_id();
        let exists = self.as_client.user_exists(user_id).await.unwrap_or(true);
        if !exists {
            let room = self
                .business_logic_context
                .config()
                .provision_room
                .clone()
                .unwrap_or_else(|| {
                    let host = url::Url::parse(&self.business_logic_context.config().matrix_server)
                        .ok()
                        .and_then(|u| u.host_str().map(|h| h.to_string()))
                        .unwrap_or_else(|| "example.com".to_string());
                    format!("!dummy:{}", host)
                });
            self.as_client.provision_user(&room).await;
        }
    }

    pub async fn sync(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(avatar) = &self.business_logic_context.config().avatar_path {
            log::info!("Using avatar {}", avatar);
        }
        Ok(())
    }

    pub async fn handle_transaction_events(&self, events: Vec<Value>) {
        for ev in events {
            let event_type = ev.get("type").and_then(|v| v.as_str());
            match event_type {
                Some("m.room.message") => {
                    if let (Some(room_id), Some(sender)) = (
                        ev.get("room_id").and_then(|r| r.as_str()),
                        ev.get("sender").and_then(|s| s.as_str()),
                    ) {
                        if sender == self.as_client.user_id() {
                            continue;
                        }
                        if let Some(content) = ev.get("content") {
                            let body = content.get("body").and_then(|b| b.as_str()).unwrap_or("");
                            let reply_event = content
                                .get("m.relates_to")
                                .and_then(|r| r.get("event_id"))
                                .and_then(|id| id.as_str());
                            self.handle_message(room_id, sender, body, reply_event).await;
                        }
                    }
                }
                Some("m.room.member") => {
                    if ev
                        .get("content")
                        .and_then(|c| c.get("membership"))
                        .and_then(|m| m.as_str())
                        == Some("invite")
                    {
                        if let Some(room_id) = ev.get("room_id").and_then(|r| r.as_str()) {
                            self.as_client.join_room(room_id).await;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    async fn handle_message(&self, room_id: &str, sender: &str, body: &str, reply_event: Option<&str>) {
        match self.extract_command(sender, room_id, body, reply_event).await {
            Ok(cmd) => {
                if let Some(cmd) = cmd {
                    match self.business_logic_context.processing_command(cmd).await {
                        Ok(reply) => {
                            if let Some(text) = reply.text {
                                self.send_message(room_id, &text).await;
                            }
                        }
                        Err(err) => {
                            log::warn!("Error processing command: {:?}", err);
                            let _ = self.send_message(room_id, "I encountered an error").await;
                        }
                    }
                }
            }
            Err(err) => {
                log::warn!("Error parsing command: {:?}", err);
            }
        }
    }

    async fn extract_command(
        &self,
        sender: &str,
        room_id: &str,
        body: &str,
        reply_event: Option<&str>,
    ) -> Result<Option<Command>, SimpleError> {
        let msg = body.trim();
        if msg.starts_with("!tip") {
            let replyee = if let Some(ev_id) = reply_event {
                if let Some(ev) = self.as_client.get_event(room_id, ev_id).await {
                    ev.get("sender")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string())
                        .ok_or_else(|| SimpleError::new("No sender"))?
                } else {
                    bail!("Cannot fetch replied event");
                }
            } else {
                bail!("Tip command must be a reply");
            };
            commands::tip(sender, msg, &replyee).map(Some)
        } else if msg.starts_with("!balance") {
            commands::balance(sender).map(Some)
        } else if msg.starts_with("!send") {
            commands::send(sender, msg).map(Some)
        } else if msg.starts_with("!invoice") {
            commands::invoice(sender, msg).map(Some)
        } else if msg.starts_with("!pay") {
            commands::pay(sender, msg).map(Some)
        } else if msg.starts_with("!help") {
            commands::help().map(Some)
        } else if msg.starts_with("!donate") {
            commands::donate(sender, msg).map(Some)
        } else if msg.starts_with("!party") {
            commands::party().map(Some)
        } else if msg.starts_with("!version") {
            commands::version().map(Some)
        } else if msg.starts_with("!generate-ln-address") {
            commands::generate_ln_address(sender, msg).map(Some)
        } else if msg.starts_with("!show-ln-addresses") {
            commands::show_ln_addresses(sender).map(Some)
        } else if msg.starts_with("!fiat-to-sats") {
            commands::fiat_to_sats(sender, msg).map(Some)
        } else if msg.starts_with("!sats-to-fiat") {
            commands::sats_to_fiat(sender, msg).map(Some)
        } else if msg.starts_with("!transactions") {
            commands::transactions(sender).map(Some)
        } else if msg.starts_with("!link-to-zeus-wallet") {
            commands::link_to_zeus_wallet(sender).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn room_is_encrypted(&self, room_id: &str) -> bool {
        {
            let cache = self.room_encryption.lock().await;
            if let Some(val) = cache.get(room_id) {
                return *val;
            }
        }
        let encrypted = match self.as_client.room_is_encrypted(room_id).await {
            Some(b) => b,
            None => false,
        };
        let mut cache = self.room_encryption.lock().await;
        cache.insert(room_id.to_string(), encrypted);
        encrypted
    }

    async fn send_message(&self, room_id: &str, body: &str) {
        if self.room_is_encrypted(room_id).await {
            let (event_type, content) = self.encryption.encrypt_text(room_id, body).await;
            self.as_client.send_raw(room_id, &event_type, content).await;
        } else {
            self.as_client.send_text(room_id, body).await;
        }
    }

    fn bot_name(&self) -> String {
        self.business_logic_context.config().registration.sender_localpart.clone()
    }
}
