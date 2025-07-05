mod commands;
mod business_logic;
mod utils;

pub mod matrix_bot {

    use matrix_sdk::{config::SyncSettings, ruma::events::room::member::{StrippedRoomMemberEvent, OriginalSyncRoomMemberEvent}, Client, Room, RoomState};

    use matrix_sdk::attachment::AttachmentConfig;
    use matrix_sdk::ruma::events::room::message::{AddMentions, ForwardThread, MessageFormat, OriginalRoomMessageEvent, OriginalSyncRoomMessageEvent, RoomMessageEventContent, TextMessageEventContent, MessageType};

    use crate::{Config, DataLayer};
    use crate::lnbits_client::lnbits_client::LNBitsClient;
    use crate::matrix_bot::business_logic::BusinessLogicContext;
    use tokio::time::{sleep, Duration};
    use std::future::Future;
    use mime;
    use matrix_sdk::ruma::{MilliSecondsSinceUnixEpoch, OwnedUserId, UserId};
    
    use simple_error::{bail, try_with};
    use simple_error::SimpleError;
    use url::Url;
    use crate::matrix_bot::commands::{balance, Command, donate, help, help_boltz_swaps, invoice, party, pay, send, tip, version, generate_ln_address, show_ln_addresses, fiat_to_sats, sats_to_fiat, transactions, link_to_zeus_wallet, boltz_onchain_to_offchain, boltz_offchain_to_onchain, refund};
    pub use crate::data_layer::data_layer::LNBitsId;
    use crate::matrix_bot::utils::parse_lnurl;


    #[derive(Debug, Clone)]
    pub(crate) struct ExtractedMessageBody {
        msg_body: Option<String>,
        formatted_msg_body: Option<String>
    }

    impl ExtractedMessageBody {
        pub(crate) fn new(msg_body: Option<String>,
               formatted_msg_body: Option<String>) -> ExtractedMessageBody {
            ExtractedMessageBody {
                msg_body,
                formatted_msg_body
            }
        }

        pub(crate) fn empty() ->  ExtractedMessageBody{
            ExtractedMessageBody::new(None, None)
        }
    }

    async fn auto_join(room_member: StrippedRoomMemberEvent,
                       client: Client,
                       room: Room,
                       business_logic_context: BusinessLogicContext) {
        if room_member.state_key != client.user_id().unwrap() {
            return;
        }

        log::info!("Autojoining room {}", room.room_id());
        let mut delay = 2;

        while let Err(err) = room.join().await {
            // retry autojoin due to synapse sending invites, before the
            // invited user can join for more information see
            // https://github.com/matrix-org/synapse/issues/4345
            log::error!("Failed to join room {} ({:?}), retrying in {}s", room.room_id(), err, delay);

            sleep(Duration::from_secs(delay)).await;
            delay *= 2;

            if delay > 3600 {
                log::error!("Can't join room {} ({:?})", room.room_id(), err);
                break;
            }
        }

        log::info!("Successfully joined room {}", room.room_id());

        // Upon successful join send a single message
        let is_direct = room.is_direct().await.unwrap_or(false);
        let is_encrypted = room.encryption_state().is_encrypted();
        let help_text = business_logic_context.get_help_content(!is_direct, is_encrypted);
        let plain = if is_encrypted {
            format!("{}\n\nThanks for inviting me. I support the following commands:\n{}",
                    crate::matrix_bot::business_logic::VERIFICATION_NOTE,
                    help_text)
        } else {
            format!("Thanks for inviting me. I support the following commands:\n{}",
                    help_text)
        };
        let html = crate::matrix_bot::utils::markdown_to_html(plain.as_str());
        let content = RoomMessageEventContent::text_html(plain, html);

        let result = room.send(content).await;

        match result {
            Err(error) => {
                log::warn!("Could not send welcome message due to {:?}..", error);
            }
            _ => { /* ignore */}
        }
    }

    fn last_line<'a>(msg_body: &str) -> String {
        msg_body.split('\n').last().unwrap().to_string()
    }

    fn sender_allowed(sender: &OwnedUserId, config: &Config) -> bool {
        if let Some(allowed) = &config.allowed_matrix_servers {
            let server = sender.server_name().as_str();
            allowed.iter().any(|s| s == server)
        } else {
            true
        }
    }

    fn strip_bot_prefix<'a>(msg: &'a str, bot_name: &str) -> Option<&'a str> {
        msg.strip_prefix(bot_name)
            .map(|rest| rest.trim_start())
            .map(|rest| rest.strip_prefix(':').unwrap_or(rest).trim_start())
    }

    pub(crate) fn parse_command(msg_body: &str) -> Result<Option<Command>, SimpleError> {
        let mut msg = msg_body.trim().to_lowercase();
        if msg.is_empty() {
            return Ok(None);
        }

        if msg.starts_with('!') {
            msg = msg[1..].to_string();
        }

        let result = match msg.split_whitespace().next() {
            Some("tip") => tip("", msg.as_str(), "").map(Some),
            Some("balance") => balance("").map(Some),
            Some("transactions") => transactions("").map(Some),
            Some("link-to-zeus-wallet") => link_to_zeus_wallet("").map(Some),
            Some("send") => send("", msg.as_str()).map(Some),
            Some("invoice") => invoice("", msg.as_str()).map(Some),
            Some("pay") => pay("", msg.as_str()).map(Some),
            Some("help-boltz-swaps") => help_boltz_swaps(true, true).map(Some),
            Some("help") => help(true, true).map(Some),
            Some("donate") => donate("", msg.as_str()).map(Some),
            Some("party") => party().map(Some),
            Some("version") => version().map(Some),
            Some("generate-ln-address") => generate_ln_address("", msg.as_str()).map(Some),
            Some("show-ln-addresses") => show_ln_addresses("").map(Some),
            Some("fiat-to-sats") => fiat_to_sats("", msg.as_str()).map(Some),
            Some("sats-to-fiat") => sats_to_fiat("", msg.as_str()).map(Some),
            Some("boltz-onchain-to-offchain") => boltz_onchain_to_offchain("", msg.as_str()).map(Some),
            Some("boltz-offchain-to-onchain") => boltz_offchain_to_onchain("", msg.as_str()).map(Some),
            Some("refund") => refund("", msg.as_str()).map(Some),
            _ => Ok(None),
        }?;

        Ok(result)
    }

    pub(crate) async fn extract_command(room: &Room,
                             sender: &str,
                             event: &OriginalSyncRoomMessageEvent,
                             extracted_msg_body: &ExtractedMessageBody,
                             business_logic_contex: &BusinessLogicContext) -> Result<Command, SimpleError> {
        let raw = extracted_msg_body.msg_body.clone().unwrap().to_lowercase();
        let mut msg_body = last_line(raw.as_str());
        let is_direct = room.is_direct().await.unwrap_or(false);
        let is_encrypted = room.encryption_state().is_encrypted();

        if !is_direct && !msg_body.starts_with('!') {
            return Ok(Command::None);
        }

        if msg_body.starts_with('!') {
            msg_body = msg_body[1..].to_string();
        }

        match parse_command(&msg_body)? {
            Some(Command::Tip { amount, memo, .. }) => {
                let replyee = extracted_msg_body
                    .formatted_msg_body
                    .as_deref()
                    .and_then(|body| extract_user_from_formatted_msg_body(body));
                let replyee = replyee.ok_or_else(|| {
                    log::warn!("Could not determine reply target from formatted body");
                    SimpleError::new("No reply target")
                })?;
                Ok(Command::Tip {
                    sender: sender.to_string(),
                    replyee: replyee.to_string(),
                    amount,
                    memo,
                })
            }
            Some(Command::Balance { .. }) => balance(sender),
            Some(Command::Transactions { .. }) => transactions(sender),
            Some(Command::LinkToZeusWallet { .. }) => link_to_zeus_wallet(sender),
            Some(Command::Send { .. }) => {
                let msg_body = preprocess_send_message(&business_logic_contex, &extracted_msg_body, room).await;
                match msg_body {
                    Ok(msg_body) => send(sender, msg_body.as_str()),
                    Err(_) => {
                          let error_message = "Please use <amount> <username>.\n                                If usernames are ambiguous write them out in full. I.e. like @username:example-server.com.";
                        if let Err(error) = send_reply_to_event_in_room(&room, &event, error_message).await {
                            log::warn!("Could not send reply message due to {:?}..", error);
                        }
                        Ok(Command::None)
                    }
                }
            }
            Some(Command::Invoice { .. }) => invoice(sender, msg_body.as_str()),
            Some(Command::Pay { .. }) => pay(sender, msg_body.as_str()),
            Some(Command::HelpBoltzSwaps { .. }) => help_boltz_swaps(!is_direct, is_encrypted),
            Some(Command::Help { .. }) => help(!is_direct, is_encrypted),
            Some(Command::Donate { amount, .. }) => Ok(Command::Donate {
                sender: sender.to_string(),
                amount,
            }),
            Some(Command::Party { .. }) => party(),
            Some(Command::Version { .. }) => version(),
            Some(Command::GenerateLnAddress { .. }) => generate_ln_address(sender, msg_body.as_str()),
            Some(Command::ShowLnAddresses { .. }) => show_ln_addresses(sender),
            Some(Command::FiatToSats { .. }) => fiat_to_sats(sender, msg_body.as_str()),
            Some(Command::SatsToFiat { .. }) => sats_to_fiat(sender, msg_body.as_str()),
            Some(Command::BoltzOnchainToOffchain { .. }) => boltz_onchain_to_offchain(sender, msg_body.as_str()),
            Some(Command::BoltzOffchainToOnchain { .. }) => boltz_offchain_to_onchain(sender, msg_body.as_str()),
            Some(Command::Refund { .. }) => refund(sender, msg_body.as_str()),
            _ => Ok(Command::None),
        }
    }

    async fn find_user_in_room(partial_user_id: &str,
                               room: &Room,
                               ctx: &BusinessLogicContext) -> Result<Option<OwnedUserId>, SimpleError> {

        log::info!("Trying to find {:?} in room ..", partial_user_id);
        if partial_user_id.is_empty() {
            return Ok(None);
        }

        // Try parsing as a full user ID first
        if let Ok(user_id) = UserId::parse(partial_user_id) {
            return Ok(room
                .get_member(&user_id)
                .await
                .map_err(|e| SimpleError::new(format!("Could not get member: {:?}", e)))?
                .map(|_| user_id.to_owned()));
        }

        let localpart = partial_user_id
            .strip_prefix('@')
            .unwrap_or(partial_user_id);

        let members: Vec<OwnedUserId> = ctx.get_or_fetch_member_ids(room).await?;

        let mut matched_user_id: Option<OwnedUserId> = None;

        for user_id in members {
            log::info!("comparing {:?} vs {:?}", user_id.localpart(), localpart);
            if user_id.localpart() == localpart {
                if matched_user_id.is_none() {
                    matched_user_id = Some(user_id.to_owned());
                } else {
                    log::info!("Found multiple possible matching user names, not returning anything");
                    return Ok(None);
                }
            }
        }

        Ok(matched_user_id)
    }

    async fn preprocess_send_message(ctx: &BusinessLogicContext,
                                     extracted_msg_body: &ExtractedMessageBody,
                                     room: &Room) -> Result<String, SimpleError> {

        log::info!("Preprocessing {:?} for send ..", extracted_msg_body);

        let raw_message = extracted_msg_body.msg_body.clone().unwrap();
        let split_message : Vec<&str> = raw_message.split_whitespace().collect();

        if split_message.len() < 3 {
            bail!("Not a valid send message")
        }

	if parse_lnurl(split_message[2]).is_some() {
            return Ok(raw_message)
        }

        let mut target_id: Option<OwnedUserId> =
            UserId::parse(split_message[2]).ok().map(|u| u.to_owned());
        target_id = if target_id.is_some() {
            target_id
        } else {
            try_with!(find_user_in_room(split_message[2], room, ctx).await,
                      "Error while trying to find user")
        };
        target_id = if target_id.is_some() { target_id }
                    else {
                        if extracted_msg_body.formatted_msg_body.is_none() {
                            None
                        } else {
                            let s = extracted_msg_body.formatted_msg_body.clone().unwrap();
                            extract_user_from_formatted_msg_body(s.as_str())
                        }
                    };

        if target_id.is_none() {
            bail!("Could not preprocess message with a valid id")
        }

        let target_id = target_id.unwrap();

        let new_message_parts = [&[split_message[0]],
                                 &[split_message[1]],
                                 &[target_id.as_str()],
                                 &split_message[3..]].concat();

        let preprocessed_message = new_message_parts.join(" ").to_string();

        log::info!("Created the following message {:?} for send ..", preprocessed_message);

        Ok(preprocessed_message)
    }

    pub(super) fn extract_user_from_formatted_msg_body(formatted_msg_body: &str) -> Option<OwnedUserId> {

        let dom = tl::parse(formatted_msg_body, tl::ParserOptions::default()).ok()?;
        let mut links = dom.query_selector("a[href]")?;
        let parser = dom.parser();
        let anchor = links.next()?.get(parser)?;

        let href = anchor
            .as_tag()?
            .attributes()
            .get("href")
            .and_then(|v| v)?;

        let href_str = href.try_as_utf8_str()?;

        let r: Vec<&str> = href_str.split('@').collect();
        if r.len() != 2 { return None; }

        let complete_id = format!("@{}", r[1]);

        OwnedUserId::try_from(complete_id).ok()
    }

    fn extract_body(event: &OriginalSyncRoomMessageEvent) -> ExtractedMessageBody {
        if let RoomMessageEventContent {
            msgtype: MessageType::Text(TextMessageEventContent { body: msg_body, formatted, .. }),
            ..
        } = &event.content
        {
            // Check if the message has formatted content
            let formatted_message_body: Option<String> = formatted.as_ref().and_then(|unwrapped| {
                match unwrapped.format {
                    MessageFormat::Html => Some(unwrapped.body.clone()), // Only support HTML
                    _ => None,
                }
            });

            // Return the extracted message body
            ExtractedMessageBody::new(Some(msg_body.clone()), formatted_message_body)
        } else {
            log::warn!("could not parse body..");
            ExtractedMessageBody::empty()
        }
    }
    async fn send_reply_to_event_in_room(room: &Room,
                                         event: &OriginalSyncRoomMessageEvent,
                                         reply: &str) -> Result<(), SimpleError> {
        let original_room_message_event = OriginalRoomMessageEvent {
            content: event.content.clone(),
            event_id: event.event_id.clone(),
            origin_server_ts: event.origin_server_ts,
            room_id: room.room_id().to_owned(),
            sender: event.sender.clone(),
            unsigned: event.unsigned.clone(),
        };

        let html = crate::matrix_bot::utils::markdown_to_html(reply);
        let reply_message = RoomMessageEventContent::text_html(reply.to_string(), html);

        let content = reply_message.make_reply_to(
            &original_room_message_event,
            ForwardThread::Yes,
            AddMentions::No
        );

        log::info!("Replying with content {:?} ..", content);

        // Send the message to the room
        room.send(content).await.map_err(|e| {
            SimpleError::new(format!("Could not send message: {:?}", e))
        })?;

        Ok(())

    }

    pub(crate) async fn poll_status<F, Fut>(interval: Duration, mut action: F) -> Option<String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        loop {
            if let Some(res) = action().await {
                return Some(res);
            }
            sleep(interval).await;
        }
    }

    pub struct MatrixBot {
        client: Client,
        business_logic_contex: BusinessLogicContext,
        config: Config
    }

    impl MatrixBot {

        pub async fn new(data_layer: DataLayer,
                         lnbits_client: LNBitsClient,
                         config: &Config ) -> matrix_sdk::Result<MatrixBot> {

            let homeserver_url =
                Url::parse(config.matrix_server.as_str())
                    .expect("Couldn't parse the homeserver URL");

            let client = Client::builder()
                .homeserver_url(homeserver_url)
                .build()
                .await
                .expect("failed to build client");

            let matrix_bot = MatrixBot {
                business_logic_contex: BusinessLogicContext::new(lnbits_client,
                                                                 data_layer,
                                                                 config),
                client,
                config: config.clone()
            };

            Ok(matrix_bot)
        }

        pub async fn init(&self) {

            log::info!("Performing init ..");

            // Dangerous
            let business_logic_context = self.business_logic_contex.clone();

            self.client.add_event_handler({
                let business_logic_context = business_logic_context.clone();
                move |room_member: StrippedRoomMemberEvent, client: Client, room: Room| {
                    let business_logic_context = business_logic_context.clone();
                    async move {
                        auto_join(room_member, client, room, business_logic_context.clone()).await;
                    }
                }
            });

            self.client.add_event_handler({
                let business_logic_context = business_logic_context.clone();
                move |_: OriginalSyncRoomMemberEvent, room: Room| {
                    let business_logic_context = business_logic_context.clone();
                    async move {
                        if let Err(e) = business_logic_context.update_room_members(&room).await {
                            log::warn!("Failed to update member cache: {:?}", e);
                        }
                    }
                }
            });

            let business_logic_contex = self.business_logic_contex.clone();
            let bot_name = self.bot_name().clone();
            let current_time = MilliSecondsSinceUnixEpoch::now();

            self.client.add_event_handler({
                let business_logic_contex = business_logic_contex.clone();
                let bot_name = bot_name.clone();
                let current_time = current_time.clone();
                move |event: OriginalSyncRoomMessageEvent, room: Room|{
                    let business_logic_contex = business_logic_contex.clone();
                    let bot_name = bot_name.clone();
                    async move {

                        if room.state() != RoomState::Joined {
                            return;
                        }

                        log::info!("processing event {:?} ..", event);

                        let sender = event.sender.as_str();
                        if event.sender.localpart() == business_logic_contex.config().matrix_username.as_str() {
                            return;
                        }
                        if !sender_allowed(&event.sender, business_logic_contex.config()) {
                            log::info!("Ignoring message from disallowed server: {}", event.sender.server_name());
                            return;
                        }
                        let extracted_msg_body = extract_body(&event);
                        if extracted_msg_body.msg_body.is_none() { return } // No body to process

                        if current_time > event.origin_server_ts {
                            // Event was before I joined, can happen in public rooms.
                            return;
                        }

                        let plain_message_body = extracted_msg_body.msg_body.clone().unwrap();
                        let mut to_process = extracted_msg_body.clone();

                        if let Some(rest) = strip_bot_prefix(&plain_message_body, bot_name.as_str()) {
                            if rest.is_empty() {
                                let result = send_reply_to_event_in_room(&room,
                                    &event,
                                    "Thanks for you message. I am but a simple bot. I will join any room you invite me to. Please run !help to see what I can do.").await;
                                if let Err(error) = result {
                                    log::warn!("Could not send reply message due to {:?}..", error);
                                }
                                return;
                            } else {
                                to_process.msg_body = Some(rest.to_string());
                            }
                        }

                        let command = extract_command(&room,
                                                      sender,
                                                      &event,
                                                      &to_process,
                                                      &business_logic_contex).await;


                        match command {
                            Err(error) => {
                                log::warn!("Error occurred while extracting command {:?}..", error);
                                let reply = error.to_string();
                                if let Err(err) = send_reply_to_event_in_room(&room, &event, reply.as_str()).await {
                                    log::warn!("Could not even send error message due to {:?}..", err);
                                }
                                return
                            }
                            _ => { },
                        };
                        let command = command.unwrap();
                        if command.is_none() {
                            // maybe this is an answer to a pending swap
                            if plain_message_body.trim().eq_ignore_ascii_case("yes") || plain_message_body.trim().eq_ignore_ascii_case("no") {
                                if business_logic_contex.has_pending_reverse_swap(sender).await {
                                    match business_logic_contex.process_reverse_swap_confirmation(sender, plain_message_body.trim()).await {
                                        Ok(Some(reply)) => {
                                            if let Err(error) = send_reply_to_event_in_room(&room, &event, reply.text.unwrap().as_str()).await {
                                                log::warn!("Could not send confirmation reply due to {:?}..", error);
                                            }
                                        }
                                        Ok(None) => {}
                                        Err(error) => {
                                            log::warn!("Error processing confirmation: {:?}", error);
                                            let _ = send_reply_to_event_in_room(&room, &event, "I seem to be experiencing a problem please try again later").await;
                                        }
                                    }
                                    return;
                                }
                            }
                            let room_is_direct = room.is_direct().await.unwrap_or(false);
                            if plain_message_body.trim_start().starts_with('!') || room_is_direct {
                                if let Err(error) = send_reply_to_event_in_room(&room,
                                                                          &event,
                                                                          "Unknown command, please use `help` for list of commands").await {
                                    log::warn!("Could not send unknown command message due to {:?}..", error);
                                }
                            }
                            return
                        } // No Command to execute

                        let command_reply = business_logic_contex.processing_command(command).await;
                        match command_reply {
                            Err(error) => {
                                log::warn!("Error occurred during business processing {:?}..", error);
                                let result = send_reply_to_event_in_room(&room,
                                                                         &event,
                                                                         "I seem to be experiencing a problem please try again later").await;
                                match result {
                                    Err(error) => {
                                        log::warn!("Could not even send error message due to {:?}..", error);
                                    }
                                    _ => { /* ignore */}
                                }
                                return
                            }
                            _ => { },
                        };
                        let command_reply = command_reply.unwrap();

                        log::info!("Sending back answer {:?}", command_reply);

                        if command_reply.is_empty() {
                            return // No output to give back
                        }

                        let send_result = send_reply_to_event_in_room(&room,
                                                                      &event,
                                                                      command_reply.text.unwrap().as_str()).await;
                        match send_result {
                            Err(error) => {
                                log::warn!("Error occurred while sending response {:?}..", error);
                                return
                            }
                            _ => { },
                        };

                        if let Some(receiver_text) = command_reply.receiver_message {
                            let content = RoomMessageEventContent::text_plain(receiver_text);
                            if let Err(error) = room.send(content).await {
                                log::warn!("Error occurred while notifying receiver {:?}..", error);
                            }
                        }

                        //
                        // TODO(AE) This assumes we don't have image only responses fix once
                        // this changes.
                        //

                        // Attaching image to message
                        if command_reply.image.is_some() {
                            let name = command_reply
                                .image_name
                                .clone()
                                .unwrap_or_else(|| "invoice.png".to_string());
                            // https://stackoverflow.com/questions/42240663/how-to-read-stdioread-from-a-vec-or-slice

                            let upload_result = room.send_attachment(name.as_str(),
                                                                     &mime::IMAGE_PNG,
                                                                     command_reply.image.unwrap(),
                                                                     AttachmentConfig::new()).await;
                            match upload_result {
                                Err(error) => {
                                    log::warn!("Error occurred while attaching image {:?}..", error);
                                    return
                                }
                                _ => { },
                            }
                        }

                        if command_reply.payment_hash.is_some() && command_reply.in_key.is_some() {
                            let payment_hash = command_reply.payment_hash.clone().unwrap();
                            let in_key = command_reply.in_key.clone().unwrap();
                            let room_clone = room.clone();
                            let ln_client = business_logic_contex.lnbits_client.clone();
                            tokio::spawn(async move {
                                let msg = poll_status(Duration::from_secs(10), || async {
                                    match ln_client.invoice_status(&in_key, &payment_hash).await {
                                        Ok(true) => Some("Invoice has been paid.".to_string()),
                                        Ok(false) => None,
                                        Err(e) => {
                                            log::warn!("Error checking invoice status: {:?}", e);
                                            Some(String::new())
                                        }
                                    }
                                }).await;
                                if let Some(text) = msg {
                                    if !text.is_empty() {
                                        let content = RoomMessageEventContent::text_plain(text);
                                        if let Err(e) = room_clone.send(content).await {
                                            log::warn!("Could not send invoice paid notification: {:?}", e);
                                        }
                                    }
                                }
                            });
                        }

                        if command_reply.swap_id.is_some() && command_reply.admin_key.is_some() {
                            let swap_id = command_reply.swap_id.clone().unwrap();
                            let admin_key = command_reply.admin_key.clone().unwrap();
                            let room_clone = room.clone();
                            let ln_client = business_logic_contex.lnbits_client.clone();
                            tokio::spawn(async move {
                                let msg = poll_status(Duration::from_secs(60), || async {
                                    match ln_client.boltz_status(&admin_key, &swap_id).await {
                                        Ok(json) => {
                                            let state = json.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                                            if state != "pending" && state != "refunding" {
                                                Some(format!("Swap {} status: {}", swap_id, state))
                                            } else {
                                                None
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("Error checking swap status: {:?}", e);
                                            Some(String::new())
                                        }
                                    }
                                }).await;
                                if let Some(text) = msg {
                                    if !text.is_empty() {
                                        let content = RoomMessageEventContent::text_plain(text);
                                        let _ = room_clone.send(content).await;
                                    }
                                }
                            });
                        }

                    }
                }
            });
        }

        fn bot_name(&self) -> String {
            match UserId::parse(self.config.matrix_username.as_str()) {
                Ok(user_id) => user_id.localpart().to_owned(),
                Err(e) => {
                    log::warn!("Could not parse my own name from config: {:?}", e);
                    "".to_string()
                }
            }
        }

        pub async fn sync(&self) -> matrix_sdk::Result<()>  {
            log::info!("Starting sync ..");

            let user_id = self.config.matrix_username.as_str();

            log::info!("Loging client in ..");

            self.client
                .matrix_auth()
                .login_username(user_id, self.config.matrix_password.as_str())
                .send()
                .await?;

            log::info!("Done with preliminary steps ..");

            let response = self.client.sync_once(SyncSettings::default()).await.unwrap();

            let settings = SyncSettings::default().token(response.next_batch);

            self.client.sync(settings).await?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matrix_bot::parse_command;
    use super::commands::Command;
    use tokio::time::Duration;
    use matrix_sdk::ruma::OwnedUserId;

    #[test]
    fn parse_tip_command() {
        let cmd = parse_command("!tip 100 thanks").unwrap();
        match cmd {
            Some(Command::Tip { amount, .. }) => assert_eq!(amount, 100),
            _ => panic!("expected tip"),
        }
    }

    #[test]
    fn parse_tip_missing_argument() {
        let err = parse_command("!tip").unwrap_err();
        assert!(err.to_string().contains("Expected"));
    }

    #[test]
    fn parse_send_missing_argument() {
        let err = parse_command("!send 50").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 2 arguments: !send <amount> <receiver> [memo]"
        );
    }

    #[test]
    fn parse_invoice_missing_argument() {
        let err = parse_command("!invoice").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 1 argument: !invoice <amount> [memo]"
        );
    }

    #[test]
    fn parse_pay_missing_argument() {
        let err = parse_command("!pay").unwrap_err();
        assert_eq!(err.to_string(), "Expected 1 argument: !pay <invoice>");
    }

    #[test]
    fn parse_donate_missing_argument() {
        let err = parse_command("!donate").unwrap_err();
        assert_eq!(err.to_string(), "Expected 1 argument: !donate <amount>");
    }

    #[test]
    fn parse_generate_ln_address_missing_argument() {
        let err = parse_command("!generate-ln-address").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 1 argument: !generate-ln-address <username>"
        );
    }

    #[test]
    fn parse_fiat_to_sats_missing_argument() {
        let err = parse_command("!fiat-to-sats 10").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 2 arguments: !fiat-to-sats <amount> <currency>"
        );
    }

    #[test]
    fn parse_sats_to_fiat_missing_argument() {
        let err = parse_command("!sats-to-fiat 10").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 2 arguments: !sats-to-fiat <amount> <currency>"
        );
    }

    #[test]
    fn parse_refund_missing_argument() {
        let err = parse_command("!refund").unwrap_err();
        assert_eq!(err.to_string(), "Expected 1 argument: !refund <swap_id>");
    }

    #[test]
    fn parse_boltz_onchain_to_offchain_missing_argument() {
        let err = parse_command("!boltz-onchain-to-offchain 100").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 2 arguments: !boltz-onchain-to-offchain <amount> <refund-address>"
        );
    }

    #[test]
    fn parse_boltz_offchain_to_onchain_missing_argument() {
        let err = parse_command("!boltz-offchain-to-onchain 100").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Expected 2 arguments: !boltz-offchain-to-onchain <amount> <onchain-address>"
        );
    }

    #[test]
    fn parse_send_command() {
        let cmd = parse_command("!send 50 @bob:example.org").unwrap();
        match cmd {
            Some(Command::Send { amount, ref recipient, .. }) => {
                assert_eq!(amount, 50);
                assert_eq!(recipient, "@bob:example.org");
            }
            _ => panic!("expected send"),
        }
    }

    #[test]
    fn parse_balance_command() {
        let cmd = parse_command("!balance").unwrap();
        assert!(matches!(cmd, Some(Command::Balance { .. })));
    }

    #[test]
    fn parse_unknown_command() {
        assert!(parse_command("!foobar").unwrap().is_none());
    }

    #[test]
    fn parse_empty_message() {
        assert!(parse_command("").unwrap().is_none());
    }

    #[test]
    fn parse_whitespace_only() {
        assert!(parse_command("   ").unwrap().is_none());
    }

    #[tokio::test]
    async fn poll_status_completes() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let counter = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let result = super::matrix_bot::poll_status(Duration::from_millis(1), move || {
            let c = c.clone();
            async move {
                let mut num = c.lock().await;
                *num += 1;
                if *num >= 3 {
                    Some("done".to_string())
                } else {
                    None
                }
            }
        })
        .await;

        assert_eq!(result.as_deref(), Some("done"));
        assert_eq!(*counter.lock().await, 3);
    }

    #[test]
    fn extract_user_from_valid_html() {
        let html = "<a href=\"https://matrix.to/#/@alice:example.org\">@alice:example.org</a>";
        let expected = OwnedUserId::try_from("@alice:example.org").unwrap();
        let result = super::matrix_bot::extract_user_from_formatted_msg_body(html);
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn extract_user_from_malformed_html() {
        let html = "<p>@alice:example.org</p>"; // missing anchor tag
        let result = super::matrix_bot::extract_user_from_formatted_msg_body(html);
        assert!(result.is_none());
    }
}
