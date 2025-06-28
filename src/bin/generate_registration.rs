use clap::{Arg, Command};
use rand::{distr::Alphanumeric, Rng};
use std::path::Path;

#[path = "../application_service/registration.rs"]
mod registration;
use registration::{Registration, Namespaces, Namespace};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("generate-registration")
        .about("Generate a Matrix application service registration file")
        .arg(Arg::new("id").long("id").required(true).help("Application service ID"))
        .arg(Arg::new("sender-localpart").long("sender-localpart").required(true).help("Localpart of the AS user"))
        .arg(Arg::new("url").long("url").required(true).help("URL the homeserver calls"))
        .arg(Arg::new("output").long("output").required(true).help("Output YAML file"))
        .get_matches();

    let id = matches.get_one::<String>("id").unwrap().to_owned();
    let sender_localpart = matches.get_one::<String>("sender-localpart").unwrap().to_owned();
    let url = matches.get_one::<String>("url").unwrap().to_owned();
    let output = matches.get_one::<String>("output").unwrap();

    let as_token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let hs_token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let namespaces = Namespaces {
        user_ids: Some(vec![Namespace {
            regex: format!("@{}:.*", sender_localpart),
            exclusive: true,
        }]),
        room_aliases: None,
        room_ids: None,
    };

    let registration = Registration {
        id,
        url,
        app_token: as_token,
        server_token: hs_token,
        sender_localpart,
        rate_limited: None,
        namespaces,
        protocols: vec![],
        soru_ephemeral_events: Some(true),
        ephemeral_events: None,
        receive_ephemeral: Some(true),
        msc3202: None,
    };

    registration.save(Path::new(output))?;
    println!("Wrote registration file to {}", output);
    Ok(())
}
