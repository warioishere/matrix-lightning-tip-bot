use simple_error::{bail, SimpleError, try_with};

#[derive(Debug)]
pub enum Command  {
    Tip     { sender: String, amount: u64, memo: Option<String>, replyee: String },
    Balance { sender: String },
    Send    { sender: String, amount: u64, recipient: String, memo: Option<String> },
    Invoice { sender: String, amount: u64, memo: Option<String> },
    Pay     { sender: String, invoice: String },
    Help    { with_prefix: bool, include_note: bool },
    HelpBoltzSwaps { with_prefix: bool, include_note: bool },
    Donate  { sender: String, amount: u64 },
    Party   { },
    Version { },
    GenerateLnAddress { sender: String, username: String },
    ShowLnAddresses { sender: String },
    FiatToSats { sender: String, amount: f64, currency: String },
    SatsToFiat { sender: String, amount: u64, currency: String },
    Transactions { sender: String },
    LinkToZeusWallet { sender: String },
    BoltzOnchainToOffchain { sender: String, amount: u64, refund_address: String },
    BoltzOffchainToOnchain { sender: String, amount: u64, onchain_address: String },
    Refund { sender: String, swap_id: String },
    None,
}

#[derive(Debug)]
pub struct CommandReply {
    pub text: Option<String>,
    pub image: Option<Vec<u8>>,
    pub image_name: Option<String>,
    pub payment_hash: Option<String>,
    pub in_key: Option<String>,
    pub receiver_message: Option<String>,
    pub swap_id: Option<String>,
    pub admin_key: Option<String>,
}

impl Command {

    pub fn is_none(&self) -> bool {
        match self {
            Command::None => true,
            _ => false
        }
    }
}

pub fn tip(sender:&str, text: &str, replyee: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 3 {
        bail!("Expected at least 2 arguments: !tip <amount> <comment>")
    }
    let amount =   try_with!(split[1].parse::<u64>(), "could not parse value");
    let memo = if split.len() > 2 { Some(split[2..].join(" ") )  }
                            else { None };
    Ok(Command::Tip { sender: sender.to_string(),
                      replyee: replyee.to_string(),
                      amount,
                      memo })
}

pub fn balance(sender:&str)  -> Result<Command, SimpleError> {
    Ok(Command::Balance { sender: String::from(sender) } )
}

pub fn send(sender:&str,
            text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();

    if split.len() < 3 {
        bail!("Expected 2 arguments: !send <amount> <receiver> [memo]")
    }
    let amount =  try_with!(split[1].parse::<u64>(), "could not parse value");
    let recipient = String::from(split[2]);
    let memo = if split.len() > 3 { Some(split[3..].join(" ") )  }
    else { None };
    Ok(Command::Send {  sender:String::from(sender),
                        amount,
                        recipient,
                        memo })
}

pub fn invoice(sender:&str,
               text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 2 {
        bail!("Expected 1 argument: !invoice <amount> [memo]")
    }
    let amount =  try_with!(split[1].parse::<u64>(), "could not parse value");
    let memo = if split.len() > 2 { Some(split[2..].join(" ") )  }
                            else { None };
    Ok(Command::Invoice { sender: String::from(sender), amount, memo })
}

pub fn pay(sender:&str,
           text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 2 {
        bail!("Expected 1 argument: !pay <invoice>")
    }
    let invoice = String::from(split[1]);
    Ok(Command::Pay { sender: String::from(sender),
                      invoice })
}

pub fn help(with_prefix: bool, include_note: bool) -> Result<Command, SimpleError> {
    Ok(Command::Help { with_prefix, include_note })
}

pub fn help_boltz_swaps(with_prefix: bool, include_note: bool) -> Result<Command, SimpleError> {
    Ok(Command::HelpBoltzSwaps { with_prefix, include_note })
}


pub fn donate(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 2 {
        bail!("Expected 1 argument: !donate <amount>")
    }
    let amount =  try_with!(split[1].parse::<u64>(), "Could not parse value");
    Ok(Command::Donate { sender: String::from(sender),
                         amount })
}

pub fn party() -> Result<Command, SimpleError> {
    Ok(Command::Party {})
}

pub fn version() -> Result<Command, SimpleError> {
    Ok(Command::Version { })
}

pub fn generate_ln_address(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 2 {
        bail!("Expected 1 argument: !generate-ln-address <username>")
    }
    let username = split[1].to_string();
    Ok(Command::GenerateLnAddress { sender: sender.to_string(), username })
}

pub fn show_ln_addresses(sender: &str) -> Result<Command, SimpleError> {
    Ok(Command::ShowLnAddresses { sender: sender.to_string() })
}

pub fn fiat_to_sats(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 3 {
        bail!("Expected 2 arguments: !fiat-to-sats <amount> <currency>");
    }
    let amount = try_with!(split[1].parse::<f64>(), "Could not parse amount");
    let currency = split[2].to_string();
    Ok(Command::FiatToSats { sender: sender.to_string(), amount, currency })
}

pub fn sats_to_fiat(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 3 {
        bail!("Expected 2 arguments: !sats-to-fiat <amount> <currency>");
    }
    let amount = try_with!(split[1].parse::<u64>(), "Could not parse amount");
    let currency = split[2].to_string();
    Ok(Command::SatsToFiat { sender: sender.to_string(), amount, currency })
}

pub fn transactions(sender: &str) -> Result<Command, SimpleError> {
    Ok(Command::Transactions { sender: sender.to_string() })
}

pub fn link_to_zeus_wallet(sender: &str) -> Result<Command, SimpleError> {
    Ok(Command::LinkToZeusWallet { sender: sender.to_string() })
}

pub fn boltz_onchain_to_offchain(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 3 {
        bail!("Expected 2 arguments: !boltz-onchain-to-offchain <amount> <refund-address>");
    }
    let amount = try_with!(split[1].parse::<u64>(), "Could not parse amount");
    let refund_address = split[2].to_string();
    Ok(Command::BoltzOnchainToOffchain { sender: sender.to_string(), amount, refund_address })
}

pub fn boltz_offchain_to_onchain(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 3 {
        bail!("Expected 2 arguments: !boltz-offchain-to-onchain <amount> <onchain-address>");
    }
    let amount = try_with!(split[1].parse::<u64>(), "Could not parse amount");
    let onchain_address = split[2].to_string();
    Ok(Command::BoltzOffchainToOnchain { sender: sender.to_string(), amount, onchain_address })
}

pub fn refund(sender: &str, text: &str) -> Result<Command, SimpleError> {
    let split = text.split_whitespace().collect::<Vec<&str>>();
    if split.len() < 2 {
        bail!("Expected 1 argument: !refund <swap_id>");
    }
    let swap_id = split[1].to_string();
    Ok(Command::Refund { sender: sender.to_string(), swap_id })
}

impl CommandReply {

    pub fn text_only(text: &str) -> CommandReply {
        CommandReply {
            text: Some(text.to_string()),
            image: None,
            image_name: None,
            payment_hash: None,
            in_key: None,
            receiver_message: None,
            swap_id: None,
            admin_key: None,
        }
    }

    pub fn new(text: &str, image: Vec<u8>) -> CommandReply {
        CommandReply {
            text: Some(text.to_string()),
            image: Some(image),
            image_name: None,
            payment_hash: None,
            in_key: None,
            receiver_message: None,
            swap_id: None,
            admin_key: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.text.is_some() && !self.image.is_some()
    }
}

