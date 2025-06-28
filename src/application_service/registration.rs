use serde::{Deserialize, Serialize};
use std::{fs, io};
use std::path::Path;
use serde_yaml;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Registration {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "url")]
    pub url: String,

    #[serde(rename = "as_token")]
    pub app_token: String,

    #[serde(rename = "hs_token")]
    pub server_token: String,

    #[serde(rename = "sender_localpart")]
    pub sender_localpart: String,

    #[serde(rename = "rate_limited", skip_serializing_if = "Option::is_none")]
    pub rate_limited: Option<bool>,

    #[serde(rename = "namespaces")]
    pub namespaces: Namespaces,

    #[serde(rename = "protocols", skip_serializing_if = "Vec::is_empty", default)]
    pub protocols: Vec<String>,

    #[serde(rename = "de.sorunome.msc2409.push_ephemeral", skip_serializing_if = "Option::is_none")]
    pub soru_ephemeral_events: Option<bool>,

    #[serde(rename = "push_ephemeral", skip_serializing_if = "Option::is_none")]
    pub ephemeral_events: Option<bool>,

    #[serde(rename = "receive_ephemeral", skip_serializing_if = "Option::is_none")]
    pub receive_ephemeral: Option<bool>,

    #[serde(rename = "org.matrix.msc3202", skip_serializing_if = "Option::is_none")]
    pub msc3202: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Namespaces {
    #[serde(rename = "users", skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<NamespaceList>,

    #[serde(rename = "aliases", skip_serializing_if = "Option::is_none")]
    pub room_aliases: Option<NamespaceList>,

    #[serde(rename = "rooms", skip_serializing_if = "Option::is_none")]
    pub room_ids: Option<NamespaceList>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Namespace {
    #[serde(rename = "regex")]
    pub regex: String,

    #[serde(rename = "exclusive")]
    pub exclusive: bool,
}

// Define NamespaceList as a vector of Namespace structs
pub type NamespaceList = Vec<Namespace>;


impl Registration {

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let data = serde_yaml::to_string(self)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        fs::write(path, data)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn load(path: &Path) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;
        let reg: Registration = serde_yaml::from_str(&data)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(reg)
    }

    // Get the YAML representation as a String
    #[allow(dead_code)]
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

}
