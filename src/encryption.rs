use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_sqlite::{SqliteCryptoStore, STATE_STORE_DATABASE_NAME};
use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use tempfile::TempDir;
use tokio::fs;
use crate::data_layer::data_layer::DataLayer;
use crate::config::config::Config;

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
}
