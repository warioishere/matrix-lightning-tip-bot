/*
 * AE: Implementation of API described at https://legend.lnbits.com/docs
 */

pub mod lnbits_client {
    use std::time::Duration;
    use serde::{Deserialize, Serialize};
    use serde_json;
    use uuid::Uuid;
    use crate::Config;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InvoiceParams {
        pub out: bool,
        pub amount: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub memo: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub webhook: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description_hash: Option<String>,
        pub unit: String,
        pub internal: bool,
    }

    impl InvoiceParams {
        pub fn simple_new(amount: u64, memo: &Option<String>) -> InvoiceParams {
            InvoiceParams {
                out: false,
                amount: amount as i64,
                memo: if memo.is_none() { Some(Uuid::new_v4().to_string()) } else { memo.clone() },
                webhook: None,
                description_hash: None, // TODO(AE): I've no idea why this should work?
                unit: "sat".to_string(),
                internal: false,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
        pub struct PaymentParams {
        pub out: bool,
        pub bolt11: String,
    }

    impl PaymentParams {
        pub fn new(out: bool, bolt11: &str) -> PaymentParams {
            PaymentParams {
                out,
                bolt11: bolt11.to_string()
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct TransferParams {
        pub memo: String,
        pub num_satoshis: i64,
        pub dest_wallet_id: String
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BitInvoice {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payment_hash: Option<String>,
        #[serde(rename = "payment_request", alias = "bolt11")]
        pub payment_request: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Wallet {
        pub id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub admin: Option<String>,
        #[serde(rename = "adminkey")]
        pub admin_key: String,
        #[serde(rename = "inkey")]
        pub in_key: String,
        pub name: String,
        pub user: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub balance: Option<u64>,
    }

    #[derive(Debug, Deserialize, Serialize)]
        pub struct WalletInfo {
            #[serde(skip_serializing_if = "Option::is_none")]
            pub balance: Option<u64>,
        }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct LnAddressRequest {
        pub description: String,
        pub wallet: String,
        pub min: u64,
        pub max: u64,
        pub currency: String,
        pub username: String,
        pub zaps: bool,
    }

    impl LnAddressRequest {
        pub fn new(username: &str, wallet_id: &str) -> LnAddressRequest {
            LnAddressRequest {
                description: "Matrix LN Address".to_string(),
                wallet: wallet_id.to_string(),
                min: 1,
                max: 500_000,
                currency: "sat".to_string(),
                username: username.to_string(),
                zaps: false,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct LnAddressResponse {
        pub lnurl: String,
    }



    #[derive(Debug, Deserialize, Serialize)]
    pub struct Error {
        pub name: String,
        pub message: String,
        pub code: String,
        pub status: String
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct LNBitsUser {
        pub id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        pub username: String,
    }

    impl LNBitsUser {
        pub fn from_id(lnbits_id: &str) -> LNBitsUser {
            LNBitsUser {
                id: lnbits_id.to_string(),
                email: None,
                username: String::new(),
            }
        }
    }

    use reqwest::{Client, header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, AUTHORIZATION}};

#[derive(Clone)]
pub struct LNBitsClient {
    pub url: String,
    pub headers: HeaderMap,
    client: Client,
    api_key: String,
}

    impl LNBitsClient {

        fn headers_with_key(&self, key: &str) -> HeaderMap {
            let mut headers = self.headers.clone();
            headers.insert("X-Api-Key", HeaderValue::from_str(key).unwrap());
            headers
        }

        fn headers_with_api_key(&self) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            headers.insert("X-Api-Key", HeaderValue::from_str(&self.api_key).unwrap());
            headers
        }

        pub fn new(config: &Config) -> LNBitsClient {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(
                    &format!("Bearer {}", config.lnbits_bearer_token)
                ).unwrap(),
            );

            LNBitsClient {
                url: config.lnbits_url.clone(),
                headers,
                client: Client::new(),
                api_key: config.lnbits_api_key.clone(),
            }
        }

        pub async fn create_user_with_initial_wallet(&self,
                                                     create_user_args: &CreateUserArgs) -> Result<LNBitsUser, reqwest::Error> {

            let response = self
                .client
                .post([self.url.as_str(), "/users/api/v1/user"].join(""))
                .headers(self.headers.clone())
                .json(create_user_args)
                .send()
                .await?
                .json::<LNBitsUser>()
                .await?;
            Ok(response)
        }

        pub async fn wallet_info(&self, wallet: &Wallet) -> Result<WalletInfo, reqwest::Error> {
            let headers = self.headers_with_key(&wallet.in_key);

            let response = self
                .client
                .get([self.url.as_str(), "/api/v1/wallet"].join(""))
                .headers(headers)
                .send()
                .await?
                .error_for_status()?;

            log::info!("Received: {:?}", response);

            let wallet_info = response.json::<WalletInfo>().await?;

            Ok(wallet_info)
        }

        pub async fn wallets(&self, user: &LNBitsUser) -> Result<Vec<Wallet>, reqwest::Error> {
            let response = self
                .client
                .get([
                    self.url.as_str(),
                    "/users/api/v1/user/",
                    &*(user.id),
                    "/wallet/",
                ]
                .join(""))
                .headers(self.headers.clone())
                .send()
                .await?
                .error_for_status()?;

            log::info!("Received: {:?}", response);

            let wallets = response.json::<Vec<Wallet>>().await?;

            Ok(wallets)
        }

        pub async fn invoice(&self,
                             wallet: &Wallet,
                             invoice_params: &InvoiceParams) -> Result<BitInvoice, reqwest::Error> {
            let headers = self.headers_with_key(&wallet.in_key);

            let response = self
                .client
                .post([self.url.as_str(), "/api/v1/payments"].join(""))
                .headers(headers)
                .json(&invoice_params)
                .send()
                .await?
                .json::<BitInvoice>()
                .await?;

            Ok(response)
        }

        // AE: Funny how the telegram bot tries to put the answer of this into a BitInvoice, I wouldn't
        pub async fn pay(&self,
                         wallet: &Wallet,
                         payment_params: &PaymentParams) -> Result<(), reqwest::Error> {
            let headers = self.headers_with_key(&wallet.admin_key);

            self
                .client
                .post([self.url.as_str(), "/api/v1/payments"].join(""))
                .headers(headers)
                .timeout(Duration::from_secs(3600))
                .json(&payment_params)
                .send()
                .await?
                .text()
                .await?;
            Ok(())
        }

        pub async fn invoice_status(&self, api_key: &str, payment_hash: &str) -> Result<bool, reqwest::Error> {
            let headers = self.headers_with_key(api_key);

            let url = [self.url.as_str(), "/api/v1/payments/", payment_hash].join("");

            let response = self
                .client
                .get(url)
                .headers(headers)
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;

            Ok(response.get("paid").and_then(|v| v.as_bool()).unwrap_or(false))
        }

        pub async fn payments(&self,
                              wallet: &Wallet,
                              limit: usize) -> Result<Vec<serde_json::Value>, reqwest::Error> {
            let headers = self.headers_with_key(&wallet.in_key);

            let url = format!("{}/api/v1/payments?limit={}", self.url, limit);

            let response = self
                .client
                .get(url)
                .headers(headers)
                .send()
                .await?
                .json::<Vec<serde_json::Value>>()
                .await?;

            Ok(response)
        }

        pub async fn create_lnurl_address(&self,
                                          request: &LnAddressRequest) -> Result<LnAddressResponse, reqwest::Error> {
            let headers = self.headers_with_api_key();

            let response = self
                .client
                .post([self.url.as_str(), "/lnurlp/api/v1/links"].join(""))
                .headers(headers)
                .json(request)
                .send()
                .await?
                .json::<LnAddressResponse>()
                .await?;

            Ok(response)
        }

        pub async fn boltz_create_swap(&self, wallet: &Wallet, amount: u64, refund_address: &str) -> Result<serde_json::Value, reqwest::Error> {
            let headers = self.headers_with_key(&wallet.admin_key);
            let url = format!("{}/boltz/api/v1/swap", self.url);
            let body = serde_json::json!({
                "wallet": wallet.id,
                "amount": amount,
                "refund_address": refund_address,
                "asset": "BTC/BTC",
                "direction": "receive",
                "feerate": false
            });
            let response = self.client.post(url).headers(headers).json(&body).send().await?.json::<serde_json::Value>().await?;
            Ok(response)
        }

        pub async fn boltz_create_reverse_swap(&self, wallet: &Wallet, amount: u64, onchain_address: &str, instant_settlement: bool) -> Result<serde_json::Value, reqwest::Error> {
            let headers = self.headers_with_key(&wallet.admin_key);
            let url = format!("{}/boltz/api/v1/swap/reverse", self.url);
            let body = serde_json::json!({
                "wallet": wallet.id,
                "amount": amount,
                "onchain_address": onchain_address,
                "instant_settlement": instant_settlement,
                "asset": "BTC/BTC",
                "direction": "send",
                "feerate": false
            });
            let response = self.client.post(url).headers(headers).json(&body).send().await?.json::<serde_json::Value>().await?;
            Ok(response)
        }

        pub async fn boltz_refund(&self, admin_key: &str, swap_id: &str) -> Result<serde_json::Value, reqwest::Error> {
            let headers = self.headers_with_key(admin_key);
            let url = format!("{}/boltz/api/v1/swap/refund?swap_id={}", self.url, swap_id);
            let response = self.client.post(url).headers(headers).send().await?.json::<serde_json::Value>().await?;
            Ok(response)
        }

        pub async fn boltz_status(&self, admin_key: &str, swap_id: &str) -> Result<serde_json::Value, reqwest::Error> {
            let headers = self.headers_with_key(admin_key);
            let url = format!("{}/boltz/api/v1/swap/status?swap_id={}", self.url, swap_id);
            let response = self.client.post(url).headers(headers).send().await?.json::<serde_json::Value>().await?;
            Ok(response)
        }
    }


    #[derive(Debug, Deserialize, Serialize)]
    pub struct CreateUserArgs {
        pub username: String,
        pub password: String,
        pub password_repeat: String,
        pub extensions: Vec<String>,
    }

    impl CreateUserArgs {
        pub fn new(username: &str, password: &str) -> CreateUserArgs {
            CreateUserArgs {
                username: String::from(username),
                password: String::from(password),
                password_repeat: String::from(password),
                extensions: vec![],
            }
        }
    }
}




