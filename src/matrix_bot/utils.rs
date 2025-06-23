use std::str::FromStr;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;

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
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\n' {
            result.push_str("<br>");
        } else if ch == '*' {
            if chars.peek() == Some(&'*') {
                chars.next();
                result.push_str("<strong>");
                while let Some(c) = chars.next() {
                    if c == '*' && chars.peek() == Some(&'*') {
                        chars.next();
                        result.push_str("</strong>");
                        break;
                    } else {
                        result.push(c);
                    }
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    result
}
