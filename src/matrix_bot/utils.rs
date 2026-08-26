use std::str::FromStr;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use pulldown_cmark::{html, Options, Parser, Event};

pub fn parse_lnurl(input: &str) -> Option<LnUrl> {
    match LnUrl::from_str(input) {
        Ok(lnurl) => Some(lnurl),
        Err(_) => match LightningAddress::from_str(input) {
            Ok(lightning_address) => Some(lightning_address.lnurl()),
            Err(_) => None
        },
    }
}

// Only checks that the string parses as an address. The network is left
// unchecked on purpose so testnet and signet deployments keep working; the
// point is to catch a mangled checksum before a swap is created around it.
pub fn is_valid_bitcoin_address(input: &str) -> bool {
    bitcoin::Address::from_str(input).is_ok()
}

pub fn markdown_to_html(input: &str) -> String {
    let parser = Parser::new_ext(input, Options::ENABLE_STRIKETHROUGH);
    let parser = parser.map(|event| match event {
        Event::SoftBreak => Event::HardBreak,
        // ensure placeholders like <invoice> are shown literally
        Event::Html(text) | Event::InlineHtml(text) => Event::Text(text.into_string().into()),
        other => other,
    });
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output
}

#[cfg(test)]
mod tests {
    use super::{markdown_to_html, is_valid_bitcoin_address};

    #[test]
    fn lowercasing_breaks_legacy_addresses_but_not_bech32() {
        // Base58 is case sensitive, so the lowercased copy of the message body
        // used to reach boltz as a refund address with a broken checksum.
        let legacy = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert!(is_valid_bitcoin_address(legacy));
        assert!(!is_valid_bitcoin_address(&legacy.to_lowercase()));

        // Bech32 is case insensitive, which is why this stayed unnoticed.
        let bech32 = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        assert!(is_valid_bitcoin_address(bech32));
        assert!(is_valid_bitcoin_address(&bech32.to_lowercase()));

        assert!(!is_valid_bitcoin_address("not-an-address"));
        assert!(!is_valid_bitcoin_address(""));
    }

    #[test]
    fn converts_basic_markdown() {
        let input = "Line 1\n**bold** and `code`";
        let html = markdown_to_html(input);
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<code>code</code>"));
        assert!(html.contains("<br"));
    }

    #[test]
    fn keeps_angle_brackets() {
        let input = "Expected 1 argument: !pay <invoice>";
        let html = markdown_to_html(input);
        assert!(html.contains("&lt;invoice&gt;"));
    }
}
