use matrix_sdk_crypto::OlmMachine;
use crate::data_layer::data_layer::DataLayer;
use crate::Config;

pub struct EncryptionHelper {
    machine: OlmMachine,
}

impl EncryptionHelper {
    pub async fn new(data_layer: &DataLayer, config: &Config) -> Self {
        let user_id = format!("@{}:{}", config.registration.sender_localpart, url::Url::parse(&config.matrix_server).unwrap().host_str().unwrap());
        let machine = OlmMachine::new(user_id.as_str().try_into().unwrap(), "ASDEVICE".into()).await;
        EncryptionHelper { machine }
    }

    pub async fn encrypt_text(&self, room_id: &str, body: &str) -> (String, serde_json::Value) {
        ("m.room.message".to_string(), serde_json::json!({"msgtype":"m.text","body":body}))
    }
}
