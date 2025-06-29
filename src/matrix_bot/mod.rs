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
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use std::sync::atomic::{AtomicBool, Ordering};

static BOT_CREATED: AtomicBool = AtomicBool::new(false);

pub struct MatrixBot {
    pub business_logic_context: BusinessLogicContext,
    as_client: MatrixAsClient,
    encryption: Arc<EncryptionHelper>,
    room_encryption: Mutex<HashMap<String, bool>>,
}

impl MatrixBot {
    pub async fn new(data_layer: DataLayer, lnbits_client: LNBitsClient, config: &Config) -> Self {
        if BOT_CREATED.swap(true, Ordering::SeqCst) {
            panic!("MatrixBot initialized multiple times");
        }
        let ctx = BusinessLogicContext::new(lnbits_client, data_layer.clone(), config);
        let as_client = MatrixAsClient::new(config, data_layer.clone());
        if let Err(e) = as_client.create_device_msc4190().await {
            log::error!("Failed to create MSC4190 device: {}", e);
        }

        let encryption = Arc::new(EncryptionHelper::new(&data_layer, config).await);
        MatrixBot {
            business_logic_context: ctx,
            as_client,
            encryption: encryption.clone(),
            room_encryption: Mutex::new(HashMap::new()),
        }
    }

    pub async fn init(self: Arc<Self>) {
        self
            .as_client
            .set_presence("online", "Ready to help")
            .await;
        self.clone().start_presence_loop();
        self.clone().start_crypto_loop();
        log::info!("MatrixBot initialized");
    }

    pub async fn sync(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(avatar) = &self.business_logic_context.config().avatar_path {
            log::info!("Using avatar {}", avatar);
            self.as_client.set_avatar_url(avatar).await;
        }
        Ok(())
    }

    pub async fn handle_transaction_events(
        self: Arc<Self>,
        events: Vec<Value>,
        send_to_device: Vec<Value>,
        device_lists: Option<Value>,
        otk_counts: Option<Value>,
    ) {
        let new_msgs = self.encryption.receive_to_device(send_to_device).await;
        for (room, sender, body) in new_msgs {
            self.clone().handle_message(&room, &sender, &body, None).await;
        }
        if let Some(lists) = device_lists {
            self.encryption.receive_device_lists(lists).await;
        }
        if let Some(counts) = otk_counts {
            self.encryption.receive_otk_counts(counts).await;
        }
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
                            self.clone().handle_message(room_id, sender, body, reply_event).await;
                        }
                    }
                }
                Some("m.room.encrypted") => {
                    if let (Some(room_id), Some(sender)) = (
                        ev.get("room_id").and_then(|r| r.as_str()),
                        ev.get("sender").and_then(|s| s.as_str()),
                    ) {
                        if sender == self.as_client.user_id() {
                            continue;
                        }
                        if let Some(body) = self
                            .encryption
                            .decrypt_event(room_id, &ev)
                            .await
                        {
                            self.clone().handle_message(room_id, sender, &body, None).await;
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
                        if let (Some(room_id), Some(state_key), Some(inviter)) = (
                            ev.get("room_id").and_then(|r| r.as_str()),
                            ev.get("state_key").and_then(|s| s.as_str()),
                            ev.get("sender").and_then(|s| s.as_str()),
                        ) {
                            if state_key == self.as_client.user_id() && self.is_user_allowed(inviter) {
                                self.as_client.accept_invite(room_id).await;
                                let welcome = self.business_logic_context.get_help_content();
                                self.clone().send_markdown_message(room_id, &welcome).await;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    async fn handle_message(self: Arc<Self>, room_id: &str, sender: &str, body: &str, reply_event: Option<&str>) {
        if !self.is_user_allowed(sender) {
            log::info!("Ignoring message from disallowed server: {}", sender);
            return;
        }
        match self.extract_command(sender, room_id, body, reply_event).await {
            Ok(cmd) => {
                if let Some(cmd) = cmd {
                    match self.business_logic_context.processing_command(cmd).await {
                        Ok(reply) => {
                            if let Some(text) = reply.text {
                                if reply.markdown {
                                    self.send_markdown_message(room_id, &text).await;
                                } else {
                                    self.send_message(room_id, &text).await;
                                }
                            }
                            if let Some(image) = reply.image {
                                self.send_image(room_id, "qr.png", image).await;
                            }
                            if let (Some(hash), Some(key)) = (reply.payment_hash, reply.in_key) {
                                self.clone().spawn_invoice_watch(room_id.to_string(), key, hash);
                            }
                            if let (Some(dm), Some(user)) = (reply.receiver_message, reply.receiver_id) {
                                self.as_client.send_dm(&user, &dm).await;
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

    async fn send_markdown_message(&self, room_id: &str, body: &str) {
        use crate::matrix_bot::utils::markdown_to_html;
        let html = markdown_to_html(body);
        if self.room_is_encrypted(room_id).await {
            let (event_type, content) = self.encryption.encrypt_html(room_id, body, &html).await;
            self.as_client.send_raw(room_id, &event_type, content).await;
        } else {
            self.as_client.send_formatted(room_id, body, &html).await;
        }
    }

    async fn send_image(&self, room_id: &str, name: &str, data: Vec<u8>) {
        if let Some(mxc) = self
            .as_client
            .upload(&data, "image/png", name)
            .await
        {
            self.as_client.send_image(room_id, name, &mxc).await;
        }
    }

    fn spawn_invoice_watch(self: Arc<Self>, room: String, in_key: String, payment_hash: String) {
        let bot = self.clone();
        tokio::spawn(async move {
            Self::watch_invoice(room, in_key, payment_hash, bot).await;
        });
    }

    async fn watch_invoice(room: String, in_key: String, payment_hash: String, bot: Arc<Self>) {
        for _ in 0..30 {
            match bot
                .business_logic_context
                .lnbits_client
                .invoice_status(&in_key, &payment_hash)
                .await
            {
                Ok(true) => {
                    let _ = bot.send_message(&room, "Invoice paid").await;
                    return;
                }
                Ok(false) => {}
                Err(err) => {
                    log::warn!("Error checking invoice status: {}", err);
                }
            }
            sleep(Duration::from_secs(10)).await;
        }
    }

    fn start_presence_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.as_client
                    .set_presence("online", "Ready to help")
                    .await;
                sleep(Duration::from_secs(300)).await;
            }
        });
    }

    fn start_crypto_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.encryption.process_outgoing_requests(&self.as_client).await;
                let msgs = self.encryption.retry_pending_events().await;
                for (room, sender, body) in msgs {
                    self.clone().handle_message(&room, &sender, &body, None).await;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }


    fn is_user_allowed(&self, user_id: &str) -> bool {
        use ruma::UserId;
        use url::Url;

        if let Some(servers) = &self.business_logic_context.config().allowed_matrix_servers {
            if let Ok(uid) = UserId::parse(user_id) {
                let server = uid.server_name().to_string();
                if let Ok(url) = Url::parse(&self.business_logic_context.config().matrix_server) {
                    if url.host_str() == Some(server.as_str()) {
                        return true;
                    }
                }
                for s in servers {
                    if let Ok(url) = Url::parse(s) {
                        if url.host_str() == Some(server.as_str()) {
                            return true;
                        }
                    }
                }
                false
            } else {
                false
            }
        } else {
            true
        }
    }
}
