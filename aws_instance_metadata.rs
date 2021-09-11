// Copyright © 2021 David Caldwell <david@porkrind.org>. MIT Licensed. See LICENSE file for details.

use aws_types::credentials::Credentials;
use hyper::Client;
use log::debug;
use serde::Deserialize;

use std::error::Error;
use std::time::Duration;

#[derive(Deserialize, Debug)]
struct Creds {
    #[serde(rename = "Code")]            code:              String,
    #[serde(rename = "LastUpdated")]     last_updated:      String,
    #[serde(rename = "Type")]            kind:              String,
    #[serde(rename = "AccessKeyId")]     access_key_id:     String,
    #[serde(rename = "SecretAccessKey")] secret_access_key: String,
    #[serde(rename = "Token")]           token:             String,
    #[serde(rename = "Expiration")]      expiration:        String
}

pub async fn get_credentials() -> Result<Credentials, Box<dyn Error>> {
    let role = http_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").await?;
    let creds_json = http_get(&format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{}", role)).await?;
    let creds: Creds = serde_json::from_str(&creds_json)?;
    Ok(Credentials::from_keys(creds.access_key_id, creds.secret_access_key, Some(creds.token)))
}

async fn http_get(uri: &str) -> Result<String, Box<dyn Error>> {
    let client = Client::new();
    let getter = client.get(uri.parse()?);
    let resp = tokio::time::timeout(Duration::from_millis(10), getter).await.map_err(|_|format!("Timed out"))??;
    debug!("resp: {:?}",resp);
    let bytes = hyper::body::to_bytes(resp.into_body()).await?;
    Ok(String::from_utf8(bytes.into_iter().collect())?)
}

