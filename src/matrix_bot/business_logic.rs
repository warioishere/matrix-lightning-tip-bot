use chrono::Utc;
use lnurl::LnUrlResponse;
use simple_error::{bail, SimpleError, try_with};
use uuid::Uuid;
use qrcode_generator::QrCodeEcc;
use crate::{Config, DataLayer, LNBitsClient};
use boltz_client::swaps::boltz::{BoltzApiClientV2, CreateSubmarineRequest, CreateReverseRequest};
use bitcoin::{PublicKey, key::rand::thread_rng, secp256k1::Keypair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;
use crate::data_layer::data_layer::{NewMatrixId2LNBitsId, NewLnAddress};
use crate::lnbits_client::lnbits_client::{BitInvoice, CreateUserArgs, InvoiceParams, LNBitsUser, PaymentParams, Wallet, WalletInfo, LnAddressRequest};
use crate::matrix_bot::commands::{Command, CommandReply};
use crate::matrix_bot::matrix_bot::LNBitsId;
use crate::matrix_bot::utils::parse_lnurl;

const HELP_COMMANDS_BASE: &str = "**!tip** - Reply to a message to tip it: `!tip <amount> [<memo>]`\n\
**!generate-ln-address** - Get your own LN Address: `!generate-ln-address <your address name>`\n\
**!show-ln-addresses** - Show your generated LN Addresses: `!show-ln-addresses`\n\
**!balance** - Check your balance: `!balance`\n\
**!send** - Send funds to a user: `!send <amount> <@user> or <@user:domain.com> or <lightningadress@yourdomain.com> [<memo>]`\n\
**!invoice** - Receive over Lightning: `!invoice <amount> [<memo>]`\n\
**!pay** - Pay an invoice over Lightning: `!pay <invoice>`\n\
**!transactions** - List your transactions: `!transactions`\n\
**!link-to-zeus-wallet** - Connect your wallet in Zeus: `!link-to-zeus-wallet`\n\
**!help** - Read this help: `!help`\n\
**!donate** - Donate to the matrix-lightning-tip-bot project: `!donate <amount>`\n\
**!party** - Start a Party: `!party`\n\
**!fiat-to-sats** - Convert fiat to satoshis: `!fiat-to-sats <amount> <currency (USD, EUR, CHF)>`\n\
**!sats-to-fiat** - Convert satoshis to fiat: `!sats-to-fiat <amount> <currency (USD, EUR, CHF)>`\n";

const HELP_COMMANDS_BOLTZ: &str = "**!boltz-onchain2offchain** - Swap on-chain BTC to Lightning: `!boltz-onchain2offchain <amount>` (bot replies with the deposit address, amount to send, swap ID for refunds and estimated Lightning payout)\n\
**!boltz-offchain2onchain** - Swap Lightning to on-chain BTC: `!boltz-offchain2onchain <amount> <btc-address>` (bot shows the expected on-chain amount after fees)\n\
**!boltz-refund** - Request a refund for a swap: `!boltz-refund <swap-id>`\n";

fn help_commands(with_prefix: bool, boltz_enabled: bool) -> String {
    let mut base = if with_prefix { HELP_COMMANDS_BASE.to_string() } else { HELP_COMMANDS_BASE.replace('!', "") };
    if boltz_enabled {
        let boltz = if with_prefix { HELP_COMMANDS_BOLTZ.to_string() } else { HELP_COMMANDS_BOLTZ.replace('!', "") };
        base.push_str(&boltz);
    }
    if with_prefix {
        base.push_str("**!version** - Print the version of this bot: `!version`");
    } else {
        base.push_str("**version** - Print the version of this bot: `version`");
    }
    base
}

pub const VERIFICATION_NOTE: &str = "Don't worry about the red 'Not verified' warning. This is a limitation of bots in the Matrix ecosystem. Your messages are still encrypted and the admin cannot read them.";

#[derive(Clone)]
pub struct BusinessLogicContext  {
    pub lnbits_client: LNBitsClient,
    pub boltz_client: Option<BoltzApiClientV2>,
    pub refund_keys: Arc<Mutex<HashMap<String, PublicKey>>>,
    data_layer: DataLayer,
    config: Config
}

impl BusinessLogicContext {

    pub fn new(lnbits_client: LNBitsClient,
               data_layer: DataLayer,
               config: &Config,
               refund_keys: Arc<Mutex<HashMap<String, PublicKey>>>) -> BusinessLogicContext {
        let boltz_client = config
            .boltz_url
            .as_ref()
            .map(|url| BoltzApiClientV2::new(url.clone(), None));
        BusinessLogicContext {
            lnbits_client,
            boltz_client,
            refund_keys,
            data_layer,
            config: config.clone()
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn get_help_content(&self, with_prefix: bool, include_note: bool) -> String {
        if include_note {
            format!(
                "{}\n\nMatrix-Lightning-Tip-Bot {}\n{}",
                VERIFICATION_NOTE,
                env!("CARGO_PKG_VERSION"),
                help_commands(with_prefix, self.boltz_client.is_some())
            )
        } else {
            format!(
                "Matrix-Lightning-Tip-Bot {}\n{}",
                env!("CARGO_PKG_VERSION"),
                help_commands(with_prefix, self.boltz_client.is_some())
            )
        }
    }

    pub async fn processing_command(&self,
                                command: Command) -> Result<CommandReply, SimpleError> {
        let command_reply = match command {
            Command::Tip { sender, amount, memo, replyee } => {
                try_with!(self.do_process_send(sender.as_str(),
                                               replyee.as_str(),
                                               amount,
                                               &memo).await,
                                               "Could not process tip.")
            },
            Command::Send { sender, amount, recipient, memo } => {
                try_with!(self.do_process_send(sender.as_str(),
                                               recipient.as_str(),
                                               amount,
                                               &memo).await,
                          "Could not process send.")
            },
            Command::Invoice { sender, amount, memo } => {
                try_with!(self.do_process_invoice(sender.as_str(),
                                                  amount,
                                                  &memo).await,
                          "Could not process invoice")
            },
            Command::Balance { sender } => {
                try_with!(self.do_process_balance(sender.as_str()).await,
                                                  "Could not process balance")
            },
            Command::Transactions { sender } => {
                try_with!(self.do_process_transactions(sender.as_str()).await,
                          "Could not process transactions")
            },
            Command::LinkToZeusWallet { sender } => {
                try_with!(self.do_process_link_to_zeus_wallet(sender.as_str()).await,
                          "Could not process link-to-zeus-wallet")
            },
            Command::Pay { sender, invoice } => {
                try_with!(self.do_process_pay(sender.as_str(), invoice.as_str()).await,
                          "Could not process pay")
            },
            Command::Help { with_prefix, include_note } => {
                try_with!(self.do_process_help(with_prefix, include_note).await,
                          "Could not process help")
            },
            Command::Donate { sender, amount } => {
                try_with!(self.do_process_donate(sender.as_str(), amount).await,
                         "Could not process donate")
            }
            Command::Party {  } => {
                try_with!(self.do_process_party().await, "Could not process party")
            },
            Command::Version { } => {
                try_with!(self.do_process_version().await, "Could not process party")
            },
            Command::GenerateLnAddress { sender, username } => {
                try_with!(self.do_process_generate_ln_address(sender.as_str(), username.as_str()).await,
                          "Could not process generate-ln-address")
            },
            Command::ShowLnAddresses { sender } => {
                try_with!(self.do_process_show_ln_addresses(sender.as_str()).await,
                          "Could not process show-ln-addresses")
            },
            Command::FiatToSats { sender, amount, currency } => {
                try_with!(self.do_process_fiat_conversion(sender.as_str(), amount, currency.as_str(), true).await,
                      "Could not process FiatToSats")
            },
            Command::SatsToFiat { sender, amount, currency } => {
                try_with!(self.do_process_fiat_conversion(sender.as_str(), amount as f64, currency.as_str(), false).await,
                      "Could not process SatsToFiat")
            },
            Command::BoltzOnchainToOffchain { sender, amount } => {
                try_with!(self.do_process_boltz_onchain2offchain(sender.as_str(), amount).await,
                          "Could not process boltz-onchain2offchain")
            },
            Command::BoltzOffchainToOnchain { sender: _, amount, address } => {
                try_with!(self.prepare_boltz_offchain2onchain(amount, address.as_str()).await,
                          "Could not prepare boltz-offchain2onchain")
            },
            Command::BoltzRefund { swap_id } => {
                try_with!(self.do_process_boltz_refund(swap_id.as_str()).await,
                          "Could not process boltz-refund")
            },
            _ => {
                log::error!("Encountered unsuported command {:?} ..", command);
                bail!("Could not process: {:?}", command)
            }
        };
        Ok(command_reply)
    }

    async fn get_fiat_to_btc_rate(&self, currency: &str) -> Result<f64, SimpleError> {
    let url = format!("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={}", currency.to_lowercase());
    log::info!("Sending request to CoinGecko for currency: {}", currency);

    let response = reqwest::get(&url).await;
    if let Err(err) = &response {
        log::error!("Error while sending request to CoinGecko: {}", err);
        return Err(SimpleError::new(err.to_string()));
    }

    let json = response.unwrap().json::<serde_json::Value>().await;
    if let Err(err) = &json {
        log::error!("Error while parsing response JSON: {}", err);
        return Err(SimpleError::new(err.to_string()));
    }

    let rate = json.unwrap()["bitcoin"][currency.to_lowercase()].as_f64().unwrap_or(0.0);
    if rate == 0.0 {
        log::error!("Received invalid rate from CoinGecko for currency: {}", currency);
        return Err(SimpleError::new("Invalid conversion rate"));
    }

    log::info!("Received conversion rate: {} for currency: {}", rate, currency);
    Ok(rate)
    }

    // Fiat in Sats umrechnen
    async fn convert_fiat_to_sats(&self, amount: f64, currency: &str) -> Result<u64, SimpleError> {
        let rate = self.get_fiat_to_btc_rate(currency).await.map_err(|e| SimpleError::new(e.to_string()))?;
        let sats = (amount / rate * 100_000_000.0) as u64;
        Ok(sats)
    }

    // Sats in Fiat umrechnen
    async fn convert_sats_to_fiat(&self, amount: u64, currency: &str) -> Result<f64, SimpleError> {
        let rate = self.get_fiat_to_btc_rate(currency).await.map_err(|e| SimpleError::new(e.to_string()))?;
        let fiat = (amount as f64 / 100_000_000.0) * rate;
        Ok(fiat)
    }

    // Die Logik für das Verarbeiten der Fiat-Befehle
    pub async fn do_process_fiat_conversion(&self, _sender: &str, amount: f64, currency: &str, is_fiat_to_sats: bool) -> Result<CommandReply, SimpleError> {
        let result = if is_fiat_to_sats {
            self.convert_fiat_to_sats(amount, currency).await.map(|sats| sats as f64)
        } else {
            self.convert_sats_to_fiat(amount as u64, currency).await
        };

        match result {
            Ok(converted) => {
                let are_or_is = if amount == 1.0 { "is" } else { "are" };
                let message = if is_fiat_to_sats {
                    format!("{:.2} {} {} approximately {} Sats.", amount, currency.to_uppercase(), are_or_is, converted)
                } else {
                    format!("{} Sats {} approximately {:.2} {}.", amount as u64, are_or_is, converted, currency.to_uppercase())
                };

                Ok(CommandReply::text_only(&message))
            }
            Err(err) => Err(err),
        }
    }

    async fn do_process_send(&self,
                             sender: &str,
                             recipient: &str,
                             amount: u64,
                             memo: &Option<String>) -> Result<CommandReply, SimpleError>  {
        log::info!("processing send command ..");

    	// If it's an LNURL, pay to the external wallet, else handle it internally
        match parse_lnurl(recipient) {
            Some(lnurl) => {
                let client = lnurl::Builder::default()
                    .build_blocking().map_err(|e| SimpleError::from(e))?;

                let res = client.make_request(&lnurl.url).map_err(|e| SimpleError::from(e))?;

                match res {
                    LnUrlResponse::LnUrlPayResponse(pay) => {
                        // Convert sats to msats
                        let res = client.get_invoice(&pay, amount * 1_000, None, match memo {
                            Some(memo) => Some(memo.as_str()),
                            None => None,
                        }).map_err(|e| SimpleError::from(e))?;

                        try_with!(self.pay_bolt11_invoice_as_matrix_is(sender, res.invoice()).await,
                            "Could not pay invoice");
                    }
                    _ => {
                        return Err(SimpleError::new("Invalid LNURL"));
                    }
                }
            },
            None => {
                let (bit_invoice, _) = try_with!(self.generate_bolt11_invoice_for_matrix_id(recipient, amount, memo).await,
                                         "Could not generate invoice");

                let bolt11_invoice = bit_invoice.payment_request;

                try_with!(self.pay_bolt11_invoice_as_matrix_is(sender, bolt11_invoice.as_str()).await,
                   "Could not pay invoice");
            }
        }
        let mut reply = if memo.is_some() {
            CommandReply::text_only(format!("{:?} sent {:?} Sats to {:?} with memo {:?}",
                                             sender,
                                             amount,
                                             recipient,
                                             memo.clone().unwrap()).as_str())
        } else {
            CommandReply::text_only(format!("{:?} sent {:?} Sats to {:?}",
                                             sender,
                                             amount,
                                             recipient).as_str())
        };

        if parse_lnurl(recipient).is_none() {
            let receiver_msg = if memo.is_some() {
                format!("{} you received {} Sats from {} with memo {}", recipient, amount, sender, memo.clone().unwrap())
            } else {
                format!("{} you received {} Sats from {}", recipient, amount, sender)
            };
            reply.receiver_message = Some(receiver_msg);
        }

        Ok(reply)
    }

    async fn do_process_invoice(&self,
                                sender: &str,
                                amount: u64,
                                memo: &Option<String>) -> Result<CommandReply, SimpleError> {
        log::info!("processing invoice command ..");

        let (bit_invoice, in_key) = try_with!(self.generate_bolt11_invoice_for_matrix_id(sender, amount, memo).await,
                                        "Could not generate invoice");

        let bolt11_invoice = bit_invoice.payment_request.clone();

        let payment_hash = bit_invoice.payment_hash.clone();

        log::info!("Generated {:?} as invoice", bolt11_invoice);

        let image: Vec<u8> = try_with!(qrcode_generator::to_png_to_vec(bolt11_invoice.as_str(),
                                                              QrCodeEcc::Medium,
                                                             256),
                                       "Could not generate QR code");

        // Insert QR code here
        let mut command_reply = CommandReply::new(bolt11_invoice.as_str(),
                                                                image);
        command_reply.payment_hash = payment_hash;
        command_reply.in_key = Some(in_key);

        Ok(command_reply)
    }

    async fn do_process_balance(&self, sender: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing balance command ..");
        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await,
                                  "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not load wallet");

        let wallet_info = try_with!(self.wallet2wallet_info(&wallet).await,
                                    "Could not load wallet info");

        let balance = wallet_info.balance;
        let balance = if balance.is_none()  { 0 }
                      else { balance.unwrap() / 1000  }; // Minisatashis are a bitch.

        Ok(CommandReply::text_only(format!("Your balance is {} Sats", balance).as_str()))
    }

    async fn do_process_transactions(&self, sender: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing transactions command ..");

        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await,
                                  "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not load wallet");

        let payments = try_with!(self.lnbits_client.payments(&wallet, 60).await,
                                 "Could not load payments");

        let mut lines: Vec<String> = Vec::new();
        for p in payments {
            if let Some(amount_msat) = p.get("amount").and_then(|v| v.as_i64()) {
                let amount_sat = amount_msat / 1000;
                let symbol = if amount_sat < 0 { "↑" } else { "↓" };
                let line = format!("{} {} Sats", symbol, amount_sat.abs());
                lines.push(line);
            }
        }

        if lines.is_empty() {
            Ok(CommandReply::text_only("No transactions found"))
        } else {
            Ok(CommandReply::text_only(lines.join("\n").as_str()))
        }
    }

    async fn do_process_pay(&self, sender: &str, bol11_invoice: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing pay command ..");

        try_with!(self.pay_bolt11_invoice_as_matrix_is(sender, bol11_invoice).await,
                  "Could not pay invoice");

        Ok(CommandReply::text_only(format!("{:?} payed an invoice", sender).as_str()))
    }

    async fn do_process_help(&self, with_prefix: bool, include_note: bool) -> Result<CommandReply, SimpleError> {
        log::info!("processing help command ..");
        Ok(CommandReply::text_only(self.get_help_content(with_prefix, include_note).as_str()))
    }

    async fn do_process_party(&self) -> Result<CommandReply, SimpleError> {
        log::info!("processing party command ..");
        Ok(CommandReply::text_only("🎉🎊🥳 let's PARTY!! 🥳🎊🎉"))
    }

    async fn do_process_version(&self) -> Result<CommandReply, SimpleError> {
        Ok(CommandReply::text_only(format!("My version is {:?}", env!("CARGO_PKG_VERSION")).as_str()))
    }

    async fn do_process_link_to_zeus_wallet(&self, sender: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing link-to-zeus-wallet command ..");

        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await,
                                  "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not load wallet");

        let mut base = self.config.lnbits_url.clone();
        if !base.ends_with('/') {
            base.push('/');
        }
        let lndhub_url = format!("lndhub://admin:{}@{}lndhub/ext/", wallet.admin_key, base);

        let image = try_with!(qrcode_generator::to_png_to_vec(
            lndhub_url.as_str(),
            QrCodeEcc::Medium,
            256
        ), "Could not generate QR code");

        Ok(CommandReply::new(lndhub_url.as_str(), image))
    }

    async fn do_process_generate_ln_address(&self, sender: &str, username: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing generate ln address command ..");

        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await,
                                  "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not load wallet");

        let params = LnAddressRequest::new(username, &wallet.id);

        let response = try_with!(self.lnbits_client.create_lnurl_address(&params).await,
                                 "Could not create ln address");

        let host = Url::parse(self.config.lnbits_url.as_str())
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_else(|| self.config.lnbits_url.clone());

        let ln_address = format!("{}@{}", username, host);
        let date_created = Utc::now().to_string();
        let new_ln_address = NewLnAddress::new(
            sender,
            ln_address.as_str(),
            response.lnurl.as_str(),
            date_created.as_str(),
        );
        self.data_layer.insert_ln_address(new_ln_address);

        Ok(CommandReply::text_only(
            format!("{} -> {}", ln_address, response.lnurl).as_str(),
        ))
    }

    async fn do_process_show_ln_addresses(&self, sender: &str) -> Result<CommandReply, SimpleError> {
        log::info!("processing show ln addresses command ..");

        let addresses = self.data_layer.ln_addresses_for_matrix_id(sender);
        if addresses.is_empty() {
            return Ok(CommandReply::text_only("No lightning addresses found"));
        }

        let lines: Vec<String> = addresses
            .iter()
            .map(|a| format!("{} -> {}", a.ln_address, a.lnurl))
            .collect();

        Ok(CommandReply::text_only(lines.join("\n").as_str()))
    }

    async fn do_process_boltz_onchain2offchain(&self, sender: &str, amount: u64) -> Result<CommandReply, SimpleError> {
        let boltz = self.boltz_client.as_ref().ok_or_else(|| SimpleError::new("Boltz not configured"))?;
        let (invoice, _) = self
            .generate_bolt11_invoice_for_matrix_id(sender, amount, &None)
            .await?;

        let pair = boltz
            .get_submarine_pairs()
            .await
            .map_err(|e| SimpleError::new(format!("{:?}", e)))?
            .get_btc_to_btc_pair()
            .ok_or_else(|| SimpleError::new("pair not found"))?;

        let net_amount = amount.saturating_sub(pair.fees.total(amount));
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let keys = Keypair::new(&secp, &mut thread_rng());
        let refund_pub = PublicKey { inner: keys.public_key(), compressed: true };
        let req = CreateSubmarineRequest {
            from: "BTC".to_string(),
            to: "BTC".to_string(),
            invoice: invoice.payment_request.clone(),
            refund_public_key: refund_pub,
            pair_hash: None,
            referral_id: None,
            webhook: None,
        };
        let resp = boltz
            .post_swap_req(&req)
            .await
            .map_err(|e| SimpleError::new(format!("{:?}", e)))?;

        self.refund_keys
            .lock()
            .await
            .insert(resp.id.clone(), refund_pub);

        let reply = format!(
            "Send exactly {} sats to {} to complete the swap (ID: {}). You will receive ~{} sats over Lightning.",
            amount,
            resp.address,
            resp.id,
            net_amount
        );
        Ok(CommandReply::text_only(reply.as_str()))
    }

    async fn prepare_boltz_offchain2onchain(
        &self,
        amount: u64,
        address: &str,
    ) -> Result<CommandReply, SimpleError> {
        let boltz = self.boltz_client.as_ref().ok_or_else(|| SimpleError::new("Boltz not configured"))?;
        let pair = boltz
            .get_reverse_pairs()
            .await
            .map_err(|e| SimpleError::new(format!("{:?}", e)))?
            .get_btc_to_btc_pair()
            .ok_or_else(|| SimpleError::new("pair not found"))?;

        let net_amount = amount.saturating_sub(pair.fees.total(amount));

        let msg = format!(
            "You are about to pay {amount} sats for a swap to {address}. You will receive ~{net_amount} sats on chain. Reply 'yes' to confirm or 'no' to cancel."
        );
        Ok(CommandReply::text_only(msg.as_str()))
    }

    pub async fn do_process_boltz_offchain2onchain(&self, sender: &str, address: &str, amount: u64) -> Result<CommandReply, SimpleError> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let keys = Keypair::new(&secp, &mut thread_rng());
        let claim_pub = PublicKey { inner: keys.public_key(), compressed: true };
        let boltz = self.boltz_client.as_ref().ok_or_else(|| SimpleError::new("Boltz not configured"))?;
        let pair = boltz
            .get_reverse_pairs()
            .await
            .map_err(|e| SimpleError::new(format!("{:?}", e)))?
            .get_btc_to_btc_pair()
            .ok_or_else(|| SimpleError::new("pair not found"))?;
        let net_amount = amount.saturating_sub(pair.fees.total(amount));
        let req = CreateReverseRequest {
            from: "BTC".to_string(),
            to: "BTC".to_string(),
            claim_public_key: claim_pub,
            invoice: None,
            invoice_amount: Some(amount),
            preimage_hash: None,
            description: None,
            description_hash: None,
            address: Some(address.to_string()),
            address_signature: None,
            referral_id: None,
            webhook: None,
        };
        let resp = boltz.post_reverse_req(req).await.map_err(|e| SimpleError::new(format!("{:?}", e)))?;
        if let Some(inv) = resp.invoice.clone() {
            self.pay_bolt11_invoice_as_matrix_is(sender, inv.as_str()).await?;
        }
        Ok(CommandReply::text_only(
            format!("Swap started with id {}. Expect ~{} sats on chain.", resp.id, net_amount).as_str(),
        ))
    }

    pub async fn do_process_boltz_refund(&self, swap_id: &str) -> Result<CommandReply, SimpleError> {
        let boltz = self.boltz_client.as_ref().ok_or_else(|| SimpleError::new("Boltz not configured"))?;
        let result = boltz
            .get_submarine_preimage(swap_id)
            .await
            .map_err(|e| SimpleError::new(format!("{:?}", e)))?;

        Ok(CommandReply::text_only(
            format!("Refund requested. Preimage: {}", result.preimage).as_str(),
        ))
    }

    async fn do_process_donate(&self, sender: &str,  amount: u64) -> Result<CommandReply, SimpleError> {
        const DONATION_ADDRESS: &str = "node-runner@btcpay.yourdevice.ch";

        let result =
            self.do_process_send(sender,
                                 DONATION_ADDRESS,
                                 amount,
                                 &Some(format!("a generouse donation from {:?}", sender))).await;
        match result {
            Ok(_) => Ok(CommandReply::text_only("Thanks for the donation")),
            Err(error) => Err(error)
        }

    }

    async fn matrix_id2lnbits_id(&self, matrix_id: &str) -> Result<LNBitsId, SimpleError> {
        if !(self.data_layer.lnbits_id_exists_for_matrix_id(matrix_id)) {

            // Only use the local part of the Matrix ID as the LNBits username
            let mut user_name = matrix_id.trim_start_matches('@');
            if let Some((name, _)) = user_name.split_once(':') {
                user_name = name;
            }

            // LNBits usernames may have a maximum length of 20 characters
            let user_name = if user_name.len() > 20 {
                &user_name[..20]
            } else {
                user_name
            };

            let password_full = Uuid::new_v4().simple().to_string();
            let password = &password_full[..8];

            let create_user_args = CreateUserArgs::new(user_name, password);
            let result = self.lnbits_client.create_user_with_initial_wallet(&create_user_args).await;
            match  result {
                Ok(result) => {
                    log::info!("created {:?} ..", result);
                    let date_created = Utc::now().to_string();
                    let new_matrix_id_2_lnbits_id = NewMatrixId2LNBitsId::new(matrix_id,
                                                                              result.id.as_str(),
                                                                              result.id.as_str(),
                                                                              date_created.as_str());
                    self.data_layer.insert_matrix_id_2_lnbits_id(new_matrix_id_2_lnbits_id);
                },
                Err(e) => {
                    // Ask how this stuff works
                    bail!("{:?}", e);
                }
            }
        }
        Ok(self.data_layer.lnbits_id_for_matrix_id(matrix_id))
    }

    async fn lnbits_id2wallet(&self, lnbits_id: &LNBitsId) -> Result<Wallet, SimpleError> {
        let lnbits_user = LNBitsUser::from_id(lnbits_id.lnbits_id.as_str());
        let mut wallets = try_with!(self.lnbits_client.wallets(&lnbits_user).await,
                                           "Could not retrieve wallets");
        if wallets.len() != 1 {
            bail!("Expected a single wallet got {:?}", wallets)
        }
        let wallet = wallets.remove(0);

        Ok(wallet)
    }

    async fn wallet2wallet_info(&self, wallet: &Wallet) -> Result<WalletInfo, SimpleError> {
        Ok(try_with!(self.lnbits_client.wallet_info(&wallet).await,
                     "Could not retrieve wallet"))
    }

    async fn pay_bolt11_invoice_as_matrix_is(&self,
                                             matrix_id: &str,
                                             bolt11_invoice: &str) -> Result<(), SimpleError> {

        let parsed_invoice: lightning_invoice::Bolt11Invoice =
            str::parse::<lightning_invoice::Bolt11Invoice>(bolt11_invoice).unwrap();

        if parsed_invoice.amount_milli_satoshis().is_none() {
            bail!( "Incorrect invoice")
        }
        let invoice_milli_satoshi_amount = parsed_invoice.amount_milli_satoshis().unwrap();

        log::info!("Got an amount for {:?} satoshis ..", invoice_milli_satoshi_amount / 1000);

        let payment_params = PaymentParams::new(true, bolt11_invoice);

        let lnbits_id = try_with!(self.matrix_id2lnbits_id(matrix_id).await,
                                          "Could not get lnbits id");

        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not get wallet");

        try_with!(self.lnbits_client.pay(&wallet, &payment_params).await,
                  "Could not perform payment");

        Ok(())
    }

    async fn generate_bolt11_invoice_for_matrix_id(&self,
                                                   matrix_id: &str,
                                                   amount: u64,
                                                   memo: &Option<String>) -> Result<(BitInvoice, String), SimpleError> {

        let lnbits_id = try_with!(self.matrix_id2lnbits_id(matrix_id).await,
                                  "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await,
                                      "Could not load wallet");
        let invoice_params = InvoiceParams::simple_new(amount, memo);

        let invoice = try_with!(self.lnbits_client.invoice(&wallet, &invoice_params).await,
                                   "Could not load invoice");

        Ok((invoice, wallet.in_key.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltz_client::swaps::boltz::{PairMinerFees, ReverseFees, SubmarineFees};

    #[test]
    fn submarine_fee_total() {
        let fees = SubmarineFees {
            percentage: 0.5,
            miner_fees: 1000,
        };
        assert_eq!(fees.total(100_000), 1500);
    }

    #[test]
    fn reverse_fee_total() {
        let fees = ReverseFees {
            percentage: 1.0,
            miner_fees: PairMinerFees { lockup: 200, claim: 300 },
        };
        assert_eq!(fees.total(50_000), 1_000);
    }

    #[tokio::test]
    async fn refund_key_storage() {
        use tokio::sync::Mutex;
        use std::collections::HashMap;
        use std::sync::Arc;
        let map: Arc<Mutex<HashMap<String, PublicKey>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut locked = map.lock().await;
            locked.insert("swap123".to_string(), PublicKey { inner: Keypair::new(&bitcoin::secp256k1::Secp256k1::new(), &mut thread_rng()).public_key(), compressed: true });
        }
        assert!(map.lock().await.contains_key("swap123"));
    }

    #[test]
    fn help_without_boltz_commands() {
        let cfg = Config::new(
            "https://example.org",
            "bot",
            "pwd",
            "http://lnbits",
            "token",
            "apikey",
            None,
            "/tmp/db",
            "Info",
            None,
        );
        let ctx = BusinessLogicContext::new(
            LNBitsClient::new(&cfg),
            DataLayer::new(&cfg),
            &cfg,
            Arc::new(Mutex::new(HashMap::new())),
        );
        let help = ctx.get_help_content(true, false);
        assert!(!help.contains("boltz-onchain2offchain"));
    }
}
