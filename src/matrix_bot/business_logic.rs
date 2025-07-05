use chrono::Utc;
use lnurl::LnUrlResponse;
use simple_error::{bail, SimpleError, try_with};
use uuid::Uuid;
use qrcode_generator::QrCodeEcc;
use crate::{Config, DataLayer, LNBitsClient};
use url::Url;
use crate::data_layer::data_layer::{NewMatrixId2LNBitsId, NewLnAddress};
use crate::lnbits_client::lnbits_client::{BitInvoice, CreateUserArgs, InvoiceParams, LNBitsUser, PaymentParams, Wallet, WalletInfo, LnAddressRequest};
use crate::matrix_bot::commands::{Command, CommandReply};
use crate::matrix_bot::matrix_bot::LNBitsId;
use crate::matrix_bot::utils::parse_lnurl;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use matrix_sdk::{Room, RoomMemberships, room::RoomMember};
use matrix_sdk::ruma::{OwnedRoomId, OwnedUserId};

const HELP_COMMANDS: &str = "**!help** - Read this help: `!help`\n\
**!help-boltz-swaps** - Learn how swaps and refunds work: `!help-boltz-swaps`\n\
**!tip** - Reply to a message to tip it: `!tip <amount> [<memo>]`\n\
**!generate-ln-address** - Get your own LN Address: `!generate-ln-address <your address name>`\n\
**!show-ln-addresses** - Show your generated LN Addresses: `!show-ln-addresses`\n\
**!balance** - Check your balance: `!balance`\n\
**!send** - Send funds to a user: `!send <amount> <@user> or <@user:domain.com> or <lightningadress@yourdomain.com> [<memo>]`\n\
**!invoice** - Receive over Lightning: `!invoice <amount> [<memo>]`\n\
**!pay** - Pay an invoice over Lightning: `!pay <invoice>`\n\
**!transactions** - List your transactions: `!transactions`\n\
**!link-to-zeus-wallet** - Connect your wallet in Zeus: `!link-to-zeus-wallet`\n\
**!donate** - Donate to the matrix-lightning-tip-bot project: `!donate <amount>`\n\
**!party** - Start a Party: `!party`\n\
**!fiat-to-sats** - Convert fiat to satoshis: `!fiat-to-sats <amount> <currency (USD, EUR, CHF)>`\n\
**!sats-to-fiat** - Convert satoshis to fiat: `!sats-to-fiat <amount> <currency (USD, EUR, CHF)>`\n\
**!boltz-onchain-to-offchain** - Swap onchain BTC to Lightning: `!boltz-onchain-to-offchain <amount> <refund-address>`\n\
**!boltz-offchain-to-onchain** - Swap Lightning to onchain BTC: `!boltz-offchain-to-onchain <amount> <onchain-address>`\n\
**!refund** - Refund a failed offchain to onchain swap: `!refund <swap_id>`\n\
**!version** - Print the version of this bot: `!version`";

const HELP_BOLTZ_SWAPS: &str = "Boltz swaps convert funds between onchain and Lightning.\n\
**!boltz-onchain-to-offchain <amount> <refund-address>** - Creates an onchain-address where you need to send onchain BTC to. Minimum 25000 sats. Boltz fees are added automatically for your requested amount. The bot notifies you when your Lightning funds arrive on your wallet. If anything goes wrong, the funds will be send back to your <refund address>.\n\
**!boltz-offchain-to-onchain <amount> <onchain-address>** - After you confirm with **yes**, the bot sends an invoice from your lightning wallet including the swap fee. The funds will then be swapped into onchain bitcoin an arrive on the supplied address. If anything goes wrong, you will be informed, but you need to use the !refund command with the swap ID to refund the lightning invoice you paid before.\n\
**!refund <swap_id>** - Requests a refund for a failed offchain to onchain swap. The bot tracks the refund and informs you once it's done.";

fn help_commands(with_prefix: bool) -> String {
    if with_prefix {
        HELP_COMMANDS.to_string()
    } else {
        HELP_COMMANDS.replace('!', "")
    }
}

fn help_boltz_swaps_text(with_prefix: bool) -> String {
    if with_prefix {
        HELP_BOLTZ_SWAPS.to_string()
    } else {
        HELP_BOLTZ_SWAPS.replace('!', "")
    }
}

pub const VERIFICATION_NOTE: &str = "Don't worry about the red 'Not verified' warning. This is a limitation of bots in the Matrix ecosystem. Your messages are still encrypted and the admin cannot read them.";

#[derive(Clone)]
pub struct BusinessLogicContext  {
    pub lnbits_client: LNBitsClient,
    data_layer: DataLayer,
    config: Config,
    pending_reverse_swaps: Arc<Mutex<HashMap<String, (u64, String)>>>,
    member_cache: Arc<Mutex<HashMap<OwnedRoomId, HashMap<String, OwnedUserId>>>>,
}

impl BusinessLogicContext {

    pub fn new(lnbits_client: LNBitsClient,
               data_layer: DataLayer,
               config: &Config) -> BusinessLogicContext {
        BusinessLogicContext {
            lnbits_client,
            data_layer,
            config: config.clone(),
            pending_reverse_swaps: Arc::new(Mutex::new(HashMap::new())),
            member_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn has_pending_reverse_swap(&self, sender: &str) -> bool {
        let map = self.pending_reverse_swaps.lock().await;
        map.contains_key(sender)
    }

    pub async fn update_room_members(&self, room: &Room) -> Result<(), SimpleError> {
        let members: Vec<RoomMember> = try_with!(
            room.members_no_sync(RoomMemberships::JOIN).await,
            "Could not get room members"
        );
        let ids: HashMap<String, OwnedUserId> = members
            .into_iter()
            .map(|m| (m.user_id().localpart().to_string(), m.user_id().to_owned()))
            .collect();
        let mut cache = self.member_cache.lock().await;
        cache.insert(room.room_id().to_owned(), ids);
        Ok(())
    }

    pub async fn get_or_fetch_member_ids(&self, room: &Room) -> Result<HashMap<String, OwnedUserId>, SimpleError> {
        if let Some(ids) = self.member_cache.lock().await.get(room.room_id()).cloned() {
            return Ok(ids);
        }
        self.update_room_members(room).await?;
        Ok(self
            .member_cache
            .lock()
            .await
            .get(room.room_id())
            .cloned()
            .unwrap_or_default())
    }

    #[cfg(test)]
    pub async fn insert_member_ids(&self, room_id: OwnedRoomId, ids: Vec<OwnedUserId>) {
        let map: HashMap<String, OwnedUserId> = ids
            .into_iter()
            .map(|id| (id.localpart().to_string(), id))
            .collect();
        let mut cache = self.member_cache.lock().await;
        cache.insert(room_id, map);
    }

    #[cfg(test)]
    pub async fn get_cached_member_ids(&self, room_id: &OwnedRoomId) -> Option<HashMap<String, OwnedUserId>> {
        let cache = self.member_cache.lock().await;
        cache.get(room_id).cloned()
    }

    pub fn get_help_content(&self, with_prefix: bool, include_note: bool) -> String {
        if include_note {
            format!(
                "{}\n\nMatrix-Lightning-Tip-Bot {}\n\n{}",
                VERIFICATION_NOTE,
                env!("CARGO_PKG_VERSION"),
                help_commands(with_prefix)
            )
        } else {
            format!(
                "Matrix-Lightning-Tip-Bot {}\n\n{}",
                env!("CARGO_PKG_VERSION"),
                help_commands(with_prefix)
            )
        }
    }

    pub fn get_help_boltz_swaps_content(&self, with_prefix: bool, include_note: bool) -> String {
        if include_note {
            format!(
                "{}\n\n{}",
                VERIFICATION_NOTE,
                help_boltz_swaps_text(with_prefix)
            )
        } else {
            help_boltz_swaps_text(with_prefix)
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
            Command::HelpBoltzSwaps { with_prefix, include_note } => {
                try_with!(self.do_process_help_boltz_swaps(with_prefix, include_note).await,
                          "Could not process help-boltz-swaps")
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
            Command::BoltzOnchainToOffchain { sender, amount, refund_address } => {
                try_with!(self.do_process_boltz_onchain_to_offchain(sender.as_str(), amount, refund_address.as_str()).await,
                          "Could not process boltz onchain to offchain")
            },
            Command::BoltzOffchainToOnchain { sender, amount, onchain_address } => {
                try_with!(self.do_process_boltz_offchain_to_onchain(sender.as_str(), amount, onchain_address.as_str()).await,
                          "Could not process boltz offchain to onchain")
            },
            Command::Refund { sender, swap_id } => {
                try_with!(self.do_process_refund(sender.as_str(), swap_id.as_str()).await,
                          "Could not process refund")
            },
            _ => {
                log::error!("Encountered unsuported command {:?} ..", command);
                bail!("Could not process: {:?}", command)
            }
        };
        Ok(command_reply)
    }

    async fn get_fiat_to_btc_rate(&self, currency: &str) -> Result<f64, SimpleError> {
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={}",
            currency.to_lowercase()
        );
        log::info!("Sending request to CoinGecko for currency: {}", currency);

        let json: serde_json::Value = reqwest::get(&url)
            .await
            .map_err(SimpleError::from)?
            .json()
            .await
            .map_err(SimpleError::from)?;

        let rate = json
            .get("bitcoin")
            .and_then(|v| v.get(&currency.to_lowercase()))
            .and_then(|v| v.as_f64())
            .ok_or_else(|| SimpleError::new("Missing conversion rate"))?;

        if rate == 0.0 {
            log::error!("Received zero rate from CoinGecko for currency: {}", currency);
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
        let parsed_lnurl = parse_lnurl(recipient);
        match &parsed_lnurl {
            Some(lnurl) => {
                let client = lnurl::Builder::default()
                    .build_async().map_err(|e| SimpleError::from(e))?;

                let res = client.make_request(&lnurl.url).await.map_err(|e| SimpleError::from(e))?;

                match res {
                    LnUrlResponse::LnUrlPayResponse(pay) => {
                        // Convert sats to msats
                        let res = client.get_invoice(&pay, amount * 1_000, None, match memo {
                            Some(memo) => Some(memo.as_str()),
                            None => None,
                        }).await.map_err(|e| SimpleError::from(e))?;

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

        if parsed_lnurl.is_none() {
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
        let mut command_reply = CommandReply::new(bolt11_invoice.as_str(), image);
        command_reply.image_name = Some("invoice.png".to_string());
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

    async fn do_process_help_boltz_swaps(&self, with_prefix: bool, include_note: bool) -> Result<CommandReply, SimpleError> {
        log::info!("processing help-boltz-swaps command ..");
        Ok(CommandReply::text_only(self.get_help_boltz_swaps_content(with_prefix, include_note).as_str()))
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

        let mut reply = CommandReply::new(lndhub_url.as_str(), image);
        reply.image_name = Some("lnurl.png".to_string());
        Ok(reply)
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

    async fn do_process_boltz_onchain_to_offchain(&self, sender: &str, amount: u64, refund_address: &str) -> Result<CommandReply, SimpleError> {
        if amount < 25_000 {
            return Ok(CommandReply::text_only("Minimum swap amount is 25000 sats"));
        }
        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await, "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await, "Could not load wallet");
        let swap = try_with!(self.lnbits_client.boltz_create_swap(&wallet, amount, refund_address).await, "Could not create swap");
        let swap_id = swap.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let address = swap.get("address").and_then(|v| v.as_str()).unwrap_or("");
        let bip21 = swap.get("bip21").and_then(|v| v.as_str()).unwrap_or("");
        let image = qrcode_generator::to_png_to_vec(bip21, QrCodeEcc::Medium, 256).map_err(SimpleError::from)?;
        let mut reply = CommandReply::new(
            &format!("Send {} sats to {} (BIP21: {}). Swap ID: {}", amount, address, bip21, swap_id),
            image,
        );
        reply.image_name = Some("send-to.png".to_string());
        reply.swap_id = Some(swap_id);
        reply.admin_key = Some(wallet.admin_key.clone());
        Ok(reply)
    }

    async fn do_process_boltz_offchain_to_onchain_impl(&self, sender: &str, amount: u64, onchain_address: &str) -> Result<CommandReply, SimpleError> {
        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await, "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await, "Could not load wallet");
        let swap = try_with!(self.lnbits_client.boltz_create_reverse_swap(&wallet, amount, onchain_address, true).await, "Could not create reverse swap");
        let swap_id = swap.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let invoice = swap.get("invoice").and_then(|v| v.as_str()).unwrap_or("");
        let mut reply = CommandReply::new(invoice, qrcode_generator::to_png_to_vec(invoice, QrCodeEcc::Medium, 256).map_err(SimpleError::from)?);
        reply.image_name = Some("invoice.png".to_string());
        reply.swap_id = Some(swap_id);
        reply.admin_key = Some(wallet.admin_key.clone());
        Ok(reply)
    }

    async fn do_process_boltz_offchain_to_onchain(&self, sender: &str, amount: u64, onchain_address: &str) -> Result<CommandReply, SimpleError> {
        if amount < 25_000 {
            return Ok(CommandReply::text_only("Minimum swap amount is 25000 sats"));
        }
        {
            let mut map = self.pending_reverse_swaps.lock().await;
            map.insert(sender.to_string(), (amount, onchain_address.to_string()));
        }
        Ok(CommandReply::text_only(&format!(
            "You are about to pay {} Sats from your lightning wallet to {}. Reply 'yes' to confirm or 'no' to abort.",
            amount, onchain_address
        )))
    }

    pub async fn process_reverse_swap_confirmation(&self, sender: &str, answer: &str) -> Result<Option<CommandReply>, SimpleError> {
        let pending = {
            let mut map = self.pending_reverse_swaps.lock().await;
            map.remove(sender)
        };
        if let Some((amount, address)) = pending {
            if answer.eq_ignore_ascii_case("yes") {
                return Ok(Some(self.do_process_boltz_offchain_to_onchain_impl(sender, amount, &address).await?));
            } else {
                return Ok(Some(CommandReply::text_only("Swap aborted")));
            }
        }
        Ok(None)
    }

    async fn do_process_refund(&self, sender: &str, swap_id: &str) -> Result<CommandReply, SimpleError> {
        let lnbits_id = try_with!(self.matrix_id2lnbits_id(sender).await, "Could not load client");
        let wallet = try_with!(self.lnbits_id2wallet(&lnbits_id).await, "Could not load wallet");
        try_with!(self.lnbits_client.boltz_refund(&wallet.admin_key, swap_id).await, "Could not refund swap");
        let mut reply = CommandReply::text_only("Refund requested");
        reply.swap_id = Some(swap_id.to_string());
        reply.admin_key = Some(wallet.admin_key.clone());
        Ok(reply)
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
            str::parse::<lightning_invoice::Bolt11Invoice>(bolt11_invoice)
                .map_err(|e| SimpleError::new(e.to_string()))?;

        let invoice_milli_satoshi_amount = parsed_invoice
            .amount_milli_satoshis()
            .ok_or_else(|| SimpleError::new("Incorrect invoice"))?;

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
    use std::collections::HashMap;

    #[tokio::test]
    async fn cache_roundtrip() {
        let config = Config::new(
            "https://example.org",
            "@bot:example.org",
            "pass",
            "https://lnbits",
            "token",
            "apikey",
            ":memory:",
            "Info",
            None,
        );
        let ctx = BusinessLogicContext::new(LNBitsClient::new(&config), DataLayer::new(&config), &config);
        let room_id = OwnedRoomId::try_from("!room:example.org").unwrap();
        let user = OwnedUserId::try_from("@alice:example.org").unwrap();

        ctx.insert_member_ids(room_id.clone(), vec![user.clone()]).await;
        let cached = ctx.get_cached_member_ids(&room_id).await.unwrap();
        let mut expected = HashMap::new();
        expected.insert(user.localpart().to_string(), user);
        assert_eq!(cached, expected);
    }

    #[tokio::test]
    async fn invalid_invoice_returns_error() {
        let config = Config::new(
            "https://example.org",
            "@bot:example.org",
            "pass",
            "https://lnbits",
            "token",
            "apikey",
            ":memory:",
            "Info",
            None,
        );
        let ctx = BusinessLogicContext::new(
            LNBitsClient::new(&config),
            DataLayer::new(&config),
            &config,
        );

        let result = ctx
            .pay_bolt11_invoice_as_matrix_is("@alice:example.org", "invalid")
            .await;

        assert!(result.is_err());
    }
}
