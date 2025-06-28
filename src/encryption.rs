use matrix_sdk_crypto::OlmMachine;
use std::pin::Pin;
use matrix_sdk_sqlite::{SqliteCryptoStore, STATE_STORE_DATABASE_NAME};
use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use tempfile::TempDir;
use tokio::fs;
use crate::data_layer::data_layer::DataLayer;
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
        let device_id: OwnedDeviceId = crate::as_client::DEVICE_ID.into();

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

    pub async fn receive_to_device(&self, events: Vec<serde_json::Value>) {
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
        }

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);
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

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);
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

        let state = fs::read(self.dir.path().join(STATE_STORE_DATABASE_NAME))
            .await
            .unwrap_or_default();
        let crypto = fs::read(self.dir.path().join("matrix-sdk-crypto.sqlite3"))
            .await
            .unwrap_or_default();
        self.data_layer.save_matrix_store(&state, &crypto);
    }

    pub async fn decrypt_event(&self, room_id: &str, event: &serde_json::Value) -> Option<String> {
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

}
