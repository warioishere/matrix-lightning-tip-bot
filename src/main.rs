#[macro_use]
extern crate diesel;
extern crate simple_error;
extern crate qrcode_generator;

mod lnbits_client;
mod config;
mod matrix_bot;
mod as_client;
mod encryption;
mod data_layer;
mod application_service;

use log::LevelFilter;
use crate::config::config::config_from_cmd;
use crate::data_layer::data_layer::DataLayer;

use crate::lnbits_client::lnbits_client::LNBitsClient;
use crate::matrix_bot::MatrixBot;

use simple_logger::SimpleLogger;
use std::str::FromStr;
use simple_error::SimpleError;
use crate::application_service::application_service::run_server;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), SimpleError>  {

    let config = config_from_cmd();

    SimpleLogger::new().with_utc_timestamps()
                       .with_level(LevelFilter::from_str(config.debug_level.as_str()).unwrap())
                       .init().unwrap();

    log::info!("Starting up.");

    let data_layer =  DataLayer::new(&config);

    let ln_client = LNBitsClient::new(&config);

    let matrix_bot: Arc<MatrixBot> = Arc::new(MatrixBot::new(data_layer, ln_client, &config).await);

    matrix_bot.init().await;
    matrix_bot.sync().await.map_err(|e| SimpleError::new(format!("{:?}", e)))?;

    run_server(matrix_bot.clone(), config.registration.clone()).await;

    Ok(())
}
