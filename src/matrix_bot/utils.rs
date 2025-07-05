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

pub fn markdown_to_html(input: &str) -> String {
    let parser = Parser::new_ext(input, Options::ENABLE_STRIKETHROUGH);
    let parser = parser.map(|event| match event {
        Event::SoftBreak => Event::HardBreak,
        other => other,
    });
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output
}

#[cfg(test)]
mod tests {
    use super::markdown_to_html;

    #[test]
    fn converts_basic_markdown() {
        let input = "Line 1\n**bold** and `code`";
        let html = markdown_to_html(input);
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<code>code</code>"));
        assert!(html.contains("<br"));
    }
}
