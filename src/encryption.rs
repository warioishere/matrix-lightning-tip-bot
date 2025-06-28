use matrix_sdk_crypto::OlmMachine;
use std::pin::Pin;
use matrix_sdk_sqlite::{SqliteCryptoStore, STATE_STORE_DATABASE_NAME};
use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use tempfile::TempDir;
use tokio::fs;
use crate::data_layer::data_layer::DataLayer;
use crate::config::config::Config;

use matrix_sdk_crypto::store::{Store, Changes};
use serde::Deserialize;

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
    data_layer: DataLayer,
    dir: TempDir,
}

impl EncryptionHelper {
    pub async fn new(data_layer: &DataLayer, config: &Config) -> Self {
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
        let device_id: OwnedDeviceId = "ASDEVICE".into();

        let dir = tempfile::tempdir().expect("create temp dir");

        if let Some((state, crypto)) = data_layer.load_matrix_store() {
            let _ = fs::write(dir.path().join(STATE_STORE_DATABASE_NAME), state).await;
            let _ = fs::write(dir.path().join("matrix-sdk-crypto.sqlite3"), crypto).await;
        }

        let store = SqliteCryptoStore::open(dir.path(), None)
            .await
            .expect("open crypto store");
        let machine = OlmMachine::with_store(&user_id, &device_id, store, None)
            .await
            .expect("create olm machine");

        EncryptionHelper { machine, data_layer: data_layer.clone(), dir }
    }

    pub async fn encrypt_text(&self, room_id: &str, body: &str, client: &crate::as_client::MatrixAsClient) -> (String, serde_json::Value) {
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

        self.process_outgoing_requests(client).await;

        // Persist store
        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);

        (
            "m.room.encrypted".to_owned(),
            serde_json::to_value(encrypted).expect("serialize encrypted"),
        )
    }

    pub async fn encrypt_html(&self, room_id: &str, body: &str, html: &str, client: &crate::as_client::MatrixAsClient) -> (String, serde_json::Value) {
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

        self.process_outgoing_requests(client).await;

        // Persist store
        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);

        (
            "m.room.encrypted".to_owned(),
            serde_json::to_value(encrypted).expect("serialize encrypted"),
        )
    }

    pub async fn receive_to_device(&self, events: Vec<serde_json::Value>, client: &crate::as_client::MatrixAsClient) {
        use matrix_sdk_crypto::{EncryptionSyncChanges};
        use ruma::{api::client::sync::sync_events::DeviceLists, serde::Raw, OneTimeKeyAlgorithm, UInt, events::AnyToDeviceEvent};
        use std::collections::BTreeMap;

        let raw_events: Vec<Raw<AnyToDeviceEvent>> = events
            .into_iter()
            .filter_map(|ev| serde_json::value::to_raw_value(&ev).ok().map(Raw::from_json))
            .collect();

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
            self.process_outgoing_requests(client).await;
        }

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);
    }

    pub async fn decrypt_event(&self, room_id: &str, event: &serde_json::Value, client: &crate::as_client::MatrixAsClient) -> Option<String> {
        use matrix_sdk_crypto::{DecryptionSettings, TrustRequirement};
        use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
        use ruma::{serde::Raw, events::{AnyMessageLikeEvent, MessageLikeEvent, room::message::MessageType}};

        let raw: Raw<EncryptedEvent> = serde_json::value::to_raw_value(event).ok().map(Raw::from_json)?;
        let room_id: OwnedRoomId = room_id.parse().ok()?;
        let settings = DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
        let decrypted = self
            .machine
            .decrypt_room_event(&raw, &room_id, &settings)
            .await
            .ok()?;

        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

        self.process_outgoing_requests(client).await;

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);

        let event = decrypted.event.deserialize().ok()?;
        if let AnyMessageLikeEvent::RoomMessage(MessageLikeEvent::Original(orig)) = event {
            if let MessageType::Text(c) = orig.content.msgtype {
                return Some(c.body);
            }
        }
        None
    }

    pub async fn process_outgoing_requests(&self, client: &crate::as_client::MatrixAsClient) {
        use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
        use ruma::api::{
            client::keys::{
            claim_keys::v3::Response as KeysClaimResponse,
            get_keys::v3::Response as KeysQueryResponse,
            upload_keys::v3::Response as KeysUploadResponse,
        },
            SendAccessToken, MatrixVersion, OutgoingRequest,
        };
        
        if let Ok(requests) = self.machine.outgoing_requests().await {
            for req in requests {
                match req.request() {
                    AnyOutgoingRequest::KeysUpload(upload) => {
                        let http_req = upload
                            .clone()
                            .try_into_http_request::<Vec<u8>>(
                                "",
                                SendAccessToken::None,
                                &[MatrixVersion::V1_1],
                            )
                            .expect("convert to http request");
                        let body: serde_json::Value =
                            serde_json::from_slice(http_req.body()).expect("parse body");
                        if client.keys_upload(body).await.is_some() {
                            if let Err(e) = self
                                .machine
                                .mark_request_as_sent(req.request_id(), &KeysUploadResponse::new(std::collections::BTreeMap::new()))
                                .await
                            {
                                log::error!("Failed to mark keys upload as sent: {}", e);
                            }
                        }
                    }
                    AnyOutgoingRequest::KeysQuery(query) => {
                        let mut device_keys = serde_json::Map::new();
                        for (user, devices) in &query.device_keys {
                            device_keys.insert(
                                user.to_string(),
                                serde_json::Value::Array(
                                    devices
                                        .iter()
                                        .map(|d| serde_json::Value::String(d.to_string()))
                                        .collect(),
                                ),
                            );
                        }
                        let body = serde_json::json!({
                            "timeout": query.timeout.map(|t| t.as_millis() as u64),
                            "device_keys": device_keys,
                        });
                        if client.keys_query(body).await.is_some() {
                            if let Err(e) = self
                                .machine
                                .mark_request_as_sent(req.request_id(), &KeysQueryResponse::new())
                                .await
                            {
                                log::error!("Failed to mark keys query as sent: {}", e);
                            }
                        }
                    }
                    AnyOutgoingRequest::KeysClaim(claim) => {
                        let http_req = claim
                            .clone()
                            .try_into_http_request::<Vec<u8>>(
                                "",
                                SendAccessToken::None,
                                &[MatrixVersion::V1_1],
                            )
                            .expect("convert to http request");
                        let body: serde_json::Value =
                            serde_json::from_slice(http_req.body()).expect("parse body");
                        if client.keys_claim(body).await.is_some() {
                            if let Err(e) = self
                                .machine
                                .mark_request_as_sent(req.request_id(), &KeysClaimResponse::new(std::collections::BTreeMap::new()))
                                .await
                            {
                                log::error!("Failed to mark keys claim as sent: {}", e);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Err(e) = self.machine.store().save().await {
            log::error!("Failed to save crypto store: {}", e);
        }

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);
    }
}
