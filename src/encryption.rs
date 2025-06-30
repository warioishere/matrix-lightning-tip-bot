use matrix_sdk_crypto::OlmMachine;
use std::pin::Pin;
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use tokio::sync::Mutex;
use crate::config::config::Config;

use matrix_sdk_crypto::store::{Store, Changes};


trait StoreSave {
    fn save(&self) -> Pin<Box<dyn std::future::Future<Output = matrix_sdk_crypto::store::Result<()>> + Send + '_>>;
}

impl StoreSave for Store {
    fn save(&self) -> Pin<Box<dyn std::future::Future<Output = matrix_sdk_crypto::store::Result<()>> + Send + '_>> {
        Box::pin(async move { self.save_changes(Changes::default()).await })
    }
}


pub struct EncryptionHelper {
    machine: OlmMachine,
    pending: tokio::sync::Mutex<Vec<(OwnedRoomId, serde_json::Value)>>,
}

impl EncryptionHelper {
    pub async fn new(config: &Config) -> Self {
        let user_id: OwnedUserId = format!(
            "@{}:{}",
            config.registration.sender_localpart,
            url::Url::parse(&config.matrix_server)
                .unwrap()
                .host_str()
                .unwrap()
        )
        .parse()
        .unwrap();
        let device_id: OwnedDeviceId = crate::as_client::DEVICE_ID.into();

        let db_path = std::path::Path::new(&config.database_url);
        let crypto_dir = db_path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let crypto_file = crypto_dir.join("crypto.sqlite3");

        let store = SqliteCryptoStore::open(&crypto_file, None)
            .await
            .expect("open crypto store");
        let machine = OlmMachine::with_store(&user_id, &device_id, store, None)
            .await
            .expect("create olm machine");

        if let Err(e) = machine.store().save().await {
            log::error!("Failed to persist crypto store: {}", e);
        }

        EncryptionHelper { machine, pending: Mutex::new(Vec::new()) }
    }

    pub async fn encrypt_text(&self, room_id: &str, body: &str) -> (String, serde_json::Value) {
        use ruma::events::{AnyMessageLikeEventContent, room::message::RoomMessageEventContent};

        let room_id: OwnedRoomId = room_id.parse().unwrap();
        let content = RoomMessageEventContent::text_plain(body);
        let encrypted = self
            .machine
            .encrypt_room_event(
                &room_id,
                AnyMessageLikeEventContent::RoomMessage(content),
            )
            .await
            .expect("encrypt");

        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

        (
            "m.room.encrypted".to_owned(),
            serde_json::to_value(encrypted).expect("serialize encrypted"),
        )
    }

    pub async fn encrypt_html(&self, room_id: &str, body: &str, html: &str) -> (String, serde_json::Value) {
        use ruma::events::{AnyMessageLikeEventContent, room::message::RoomMessageEventContent};

        let room_id: OwnedRoomId = room_id.parse().unwrap();
        let content = RoomMessageEventContent::text_html(body.to_owned(), html.to_owned());
        let encrypted = self
            .machine
            .encrypt_room_event(
                &room_id,
                AnyMessageLikeEventContent::RoomMessage(content),
            )
            .await
            .expect("encrypt");

        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

        (
            "m.room.encrypted".to_owned(),
            serde_json::to_value(encrypted).expect("serialize encrypted"),
        )
    }

    pub async fn receive_to_device(&self, events: Vec<serde_json::Value>) -> Vec<(String, String, String)> {
        use matrix_sdk_crypto::EncryptionSyncChanges;
        use ruma::{api::client::sync::sync_events::DeviceLists, serde::Raw, OneTimeKeyAlgorithm, UInt, events::AnyToDeviceEvent};
        use std::collections::BTreeMap;

        log::debug!("receive_to_device events: {:?}", events);

        let raw_events: Vec<Raw<AnyToDeviceEvent>> = events
            .into_iter()
            .filter_map(|ev| serde_json::value::to_raw_value(&ev).ok().map(Raw::from_json))
            .collect();

        for raw_ev in &raw_events {
            if let Ok(ev) = raw_ev.deserialize() {
                if let AnyToDeviceEvent::RoomKey(key) = ev {
                    log::debug!(
                        "Received room key for room {} session {}",
                        key.content.room_id,
                        key.content.session_id
                    );
                }
            }
        }

        let changes = EncryptionSyncChanges {
            to_device_events: raw_events,
            changed_devices: &DeviceLists::new(),
            one_time_keys_counts: &BTreeMap::<OneTimeKeyAlgorithm, UInt>::new(),
            unused_fallback_keys: None,
            next_batch_token: None,
        };

        if !changes.to_device_events.is_empty() {
            if let Err(e) = self.machine.receive_sync_changes(changes).await {
                log::error!("Error processing to-device events: {}", e);
            }
            if let Err(e) = self.machine.store().save().await {
                log::error!("Failed to save crypto store: {}", e);
            }
        }

        self.retry_pending_events().await
    }

    pub async fn receive_device_lists(&self, lists: serde_json::Value) {
        use matrix_sdk_crypto::EncryptionSyncChanges;
        use ruma::{api::client::sync::sync_events::DeviceLists, OneTimeKeyAlgorithm, UInt};
        use std::collections::BTreeMap;

        let device_lists: DeviceLists = serde_json::from_value(lists).unwrap_or_else(|_| DeviceLists::new());
        let counts = BTreeMap::<OneTimeKeyAlgorithm, UInt>::new();

        let changes = EncryptionSyncChanges {
            to_device_events: Vec::new(),
            changed_devices: &device_lists,
            one_time_keys_counts: &counts,
            unused_fallback_keys: None,
            next_batch_token: None,
        };

        if let Err(e) = self.machine.receive_sync_changes(changes).await {
            log::error!("Error processing device lists: {}", e);
        }
        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

    }

    pub async fn receive_otk_counts(&self, counts_json: serde_json::Value) {
        use matrix_sdk_crypto::EncryptionSyncChanges;
        use ruma::{api::client::sync::sync_events::DeviceLists, OneTimeKeyAlgorithm, UInt};
        use std::collections::BTreeMap;

        let mut counts = BTreeMap::<OneTimeKeyAlgorithm, UInt>::new();
        if let Some(map) = counts_json.as_object() {
            for (k, v) in map {
                if let Some(num) = v.as_u64() {
                    let alg = OneTimeKeyAlgorithm::from(k.as_str());
                    counts.insert(alg, UInt::from(num as u32));
                }
            }
        }
        let device_lists = DeviceLists::new();

        let changes = EncryptionSyncChanges {
            to_device_events: Vec::new(),
            changed_devices: &device_lists,
            one_time_keys_counts: &counts,
            unused_fallback_keys: None,
            next_batch_token: None,
        };

        if let Err(e) = self.machine.receive_sync_changes(changes).await {
            log::error!("Error processing one-time key counts: {}", e);
        }
        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

    }

    pub async fn decrypt_event(&self, room_id: &str, event: &serde_json::Value) -> Option<String> {
        let room_id: OwnedRoomId = room_id.parse().ok()?;
        self.decrypt_event_internal(&room_id, event, true).await
    }

    async fn decrypt_event_internal(
        &self,
        room_id: &OwnedRoomId,
        event: &serde_json::Value,
        queue_on_missing: bool,
    ) -> Option<String> {
        use matrix_sdk_crypto::{DecryptionSettings, TrustRequirement};
        use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
        use ruma::{serde::Raw, events::{AnyMessageLikeEvent, MessageLikeEvent, room::message::MessageType}};

        let raw: Raw<EncryptedEvent> = serde_json::value::to_raw_value(event).ok().map(Raw::from_json)?;
        let settings = DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
        let decrypted = match self
            .machine
            .decrypt_room_event(&raw, room_id, &settings)
            .await
        {
            Ok(ev) => ev,
            Err(matrix_sdk_crypto::MegolmError::MissingRoomKey(_)) => {
                if queue_on_missing {
                    log::debug!("Missing room key, queueing event for retry");
                    {
                        let mut p = self.pending.lock().await;
                        p.push((room_id.clone(), event.clone()));
                    }
                    let _ = self.machine.request_room_key(&raw, room_id).await;
                }
                return None;
            }
            Err(_) => return None,
        };

        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }



        let event = decrypted.event.deserialize().ok()?;
        if let AnyMessageLikeEvent::RoomMessage(MessageLikeEvent::Original(orig)) = event {
            if let MessageType::Text(c) = orig.content.msgtype {
                return Some(c.body);
            }
        }
        None
    }



    pub async fn process_and_send_outgoing_requests(&self, client: &crate::as_client::MatrixAsClient) {
        use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
        use ruma::api::client::keys::get_keys;

        let requests = self.machine.outgoing_requests().await.unwrap_or_default();
        for req in requests {
            match req.request() {
                AnyOutgoingRequest::KeysUpload(upload) => {
                    match client.keys_upload(upload.clone()).await {
                        Some((resp, status)) if status.is_success() => {
                            self.machine
                                .mark_request_as_sent(req.request_id(), &resp)
                                .await
                                .unwrap();
                        }
			Some((_, status)) => {
    			    log::warn!("keys_upload failed with status {}", status.as_u16());
    			    // Mark as sent to avoid retry loop
    			    self.machine
        			.mark_request_as_sent(
            			req.request_id(),
            			&ruma::api::client::keys::upload_keys::v3::Response::new(
                		    std::collections::BTreeMap::new()
            			),
        		    )
        		    .await
        		    .unwrap();
			}
                        None => {
                            log::warn!("keys_upload request failed");
                        }
                    }
                }
                AnyOutgoingRequest::KeysQuery(query) => {
                    let mut body = get_keys::v3::Request::new();
                    body.device_keys = query.device_keys.clone();
                    match client.keys_query(body).await {
                        Some((resp, status)) if status.is_success() => {
                            self.machine
                                .mark_request_as_sent(req.request_id(), &resp)
                                .await
                                .unwrap();
                        }
                        Some((_, status)) => {
                            log::warn!("keys_query failed with status {}", status.as_u16());
                        }
                        None => {
                            log::warn!("keys_query request failed");
                        }
                    }
                }
                AnyOutgoingRequest::KeysClaim(claim) => {
                    match client.keys_claim(claim.clone()).await {
                        Some((resp, status)) if status.is_success() => {
                            self.machine
                                .mark_request_as_sent(req.request_id(), &resp)
                                .await
                                .unwrap();
                        }
                        Some((_, status)) => {
                            log::warn!("keys_claim failed with status {}", status.as_u16());
                        }
                        None => {
                            log::warn!("keys_claim request failed");
                        }
                    }
                }
                AnyOutgoingRequest::ToDeviceRequest(td) => {
                    match client.send_to_device(td.clone()).await {
                        Some(resp) => {
                            self.machine
                                .mark_request_as_sent(req.request_id(), &resp)
                                .await
                                .unwrap();
                        }
                        None => {
                            log::warn!("to_device request failed");
                        }
                    }
                }
                _ => {}
            }
        }
        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

    }

    pub async fn process_outgoing_requests(&self, client: &crate::as_client::MatrixAsClient) {
        self.process_and_send_outgoing_requests(client).await;
    }

    pub async fn share_keys_if_needed(&self, client: &crate::as_client::MatrixAsClient) {
        self.process_and_send_outgoing_requests(client).await;
    }

    pub async fn retry_pending_events(&self) -> Vec<(String, String, String)> {
        let mut pending = self.pending.lock().await;
        if pending.is_empty() {
            return Vec::new();
        }
        log::debug!("Retrying {} pending events", pending.len());
        let mut results = Vec::new();
        let mut i = 0usize;
        while i < pending.len() {
            let (room_id, event) = pending[i].clone();
            if let Some(sender) = event.get("sender").and_then(|s| s.as_str()) {
                if let Some(body) = self
                    .decrypt_event_internal(&room_id, &event, false)
                    .await
                {
                    results.push((room_id.to_string(), sender.to_string(), body));
                    pending.remove(i);
                    log::debug!("Pending event decrypted for room {}", room_id);
                    continue;
                }
            }
            i += 1;
        }
        results
    }

}
