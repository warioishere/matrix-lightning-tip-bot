use crate::{Config, DataLayer, LNBitsClient};
mod commands;
mod business_logic;
mod utils;
pub use crate::data_layer::data_layer::LNBitsId;
use self::business_logic::BusinessLogicContext;
use self::commands::Command;
use crate::as_client::MatrixAsClient;
use crate::encryption::EncryptionHelper;
use serde_json::Value;
use simple_error::{SimpleError, bail, try_with};

pub struct MatrixBot {
    pub business_logic_context: BusinessLogicContext,
    as_client: MatrixAsClient,
    encryption: EncryptionHelper,
}

impl MatrixBot {
    pub async fn new(data_layer: DataLayer, lnbits_client: LNBitsClient, config: &Config) -> Self {
        let ctx = BusinessLogicContext::new(lnbits_client, data_layer.clone(), config);
        let as_client = MatrixAsClient::new(config);
        let encryption = EncryptionHelper::new(&data_layer, config).await;
        MatrixBot { business_logic_context: ctx, as_client, encryption }
    }

    pub async fn init(&self) {
        // nothing for now
    }

    pub async fn sync(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(avatar) = &self.business_logic_context.config().avatar_path {
            // avatar URL already in registration; skip uploading
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
                                .and_then(|r| r.get("m.in_reply_to"))
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
                if cmd.is_none() {
                    return;
                }
                match self.business_logic_context.processing_command(cmd).await {
                    Ok(reply) => {
                        if let Some(text) = reply.text {
                            self.as_client.send_text(room_id, &text).await;
                        }
                    }
                    Err(err) => {
                        log::warn!("Error processing command: {:?}", err);
                        let _ = self.as_client.send_text(room_id, "I encountered an error").await;
                    }
                }
            }
            Err(err) => {
                log::warn!("Error parsing command: {:?}", err);
            }
        }
    }

    async fn extract_command(&self, sender: &str, room_id: &str, body: &str, reply_event: Option<&str>) -> Result<Command, SimpleError> {
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
            commands::tip(sender, msg, &replyee)
        } else if msg.starts_with("!balance") {
            commands::balance(sender)
        } else if msg.starts_with("!send") {
            commands::send(sender, msg)
        } else if msg.starts_with("!invoice") {
            commands::invoice(sender, msg)
        } else if msg.starts_with("!pay") {
            commands::pay(sender, msg)
        } else if msg.starts_with("!help") {
            commands::help()
        } else if msg.starts_with("!donate") {
            commands::donate(sender, msg)
        } else if msg.starts_with("!party") {
            commands::party()
        } else if msg.starts_with("!version") {
            commands::version()
        } else if msg.starts_with("!generate-ln-address") {
            commands::generate_ln_address(sender, msg)
        } else if msg.starts_with("!show-ln-addresses") {
            commands::show_ln_addresses(sender)
        } else if msg.starts_with("!fiat-to-sats") {
            commands::fiat_to_sats(sender, msg)
        } else if msg.starts_with("!sats-to-fiat") {
            commands::sats_to_fiat(sender, msg)
        } else if msg.starts_with("!transactions") {
            commands::transactions(sender)
        } else if msg.starts_with("!link-to-zeus-wallet") {
            commands::link_to_zeus_wallet(sender)
        } else {
            Ok(Command::None)
        }
    }

    fn bot_name(&self) -> String {
        self.business_logic_context.config().registration.sender_localpart.clone()
    }
}
