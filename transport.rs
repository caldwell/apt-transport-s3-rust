// Copyright © 2021 David Caldwell <david@porkrind.org>. MIT Licensed. See LICENSE file for details.

use chrono::{Local};
use log::{warn,debug,trace};
use tokio::io::{AsyncWriteExt,AsyncBufReadExt};

use std::error::Error;

mod messages;
use messages::{RawAptMessage,AptMessage,Capabilities,Status,URIStart,URIDone,URIFailure,GeneralFailure,URIAcquire,ToRaw,FromRaw};
mod aws_instance_metadata;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    stderrlog::new()
        .verbosity(log::LevelFilter::Trace as usize - 1)
        .quiet(std::env::var_os("APT_TRANSPORT_S3_DEBUG").is_none())
        .show_level(true)
        .module(module_path!())
        .init()?;

    let config = match aws_instance_metadata::get_credentials().await {
        Ok(creds) => aws_config::from_env().credentials_provider(creds).load().await,
        _ => aws_config::from_env().load().await,
    };
    let client = aws_sdk_s3::Client::new(&config);

    let mut apt_message = AptMessageResponder::new(client, tokio::io::stdin(), tokio::io::stdout());
    apt_message.handle_messages().await?;

    Ok(())
}

// documented (lightly) in the `libapt-pkg-doc` package (/usr/share/doc/libapt-pkg-doc/method.text.gz):

#[derive(Debug)]
struct AptMessageResponder<R,W> {
    in_lines: tokio::io::Lines<tokio::io::BufReader<R>>,
    out: W,
    s3: aws_sdk_s3::Client,
}

impl<R,W> AptMessageResponder<R,W> where
    R: tokio::io::AsyncRead + std::marker::Unpin,
    W: tokio::io::AsyncWrite + std::marker::Unpin
{
    fn new(s3: aws_sdk_s3::Client, reader: R, writer: W) -> AptMessageResponder<R,W> {
        let buf_reader = tokio::io::BufReader::new(reader);
        AptMessageResponder { s3, in_lines: buf_reader.lines(), out: writer }
    }
    async fn handle_messages(&mut self) -> Result<(), Box<dyn Error>> {
        self.send_message(AptMessage::Capabilities(Capabilities{
            version: "0.0.0".to_owned(),
            single_instance: true,
            local_only: false,
            pipeline: false,
            send_config: true,
            needs_cleanup: false,
            removable: false,
            aux_requests: false,
            send_uri_encode: false,
        })).await?;

        loop {
            let message = self.get_message().await?;
            match message {
                AptMessage::Configuration(_) => { /* FIXME */ },
                AptMessage::URIAcquire(ref uri_acquire) => {
                    match self.acquire_uri(uri_acquire).await {
                        Ok(()) => {},
                        Err(e) => { self.send_uri_failure(&uri_acquire.uri, &e.to_string()).await? }
                    }
                },
                _ => {
                    warn!("Unhandled message: {:?}", message);
                    self.send_message(AptMessage::GeneralFailure(GeneralFailure{ message: format!("Unknown message: {:?}", message) })).await?;
                },
            }
        }
    }

    async fn get_message(&mut self) -> Result<AptMessage, Box<dyn Error>> {
        let mut lines: Vec<String> = vec![];
        loop {
            let line = self.in_lines.next_line().await?.ok_or("Input file closed").map(|l|l.trim().to_string())?;
            if line == "" { break }
            lines.push(line);
        }
        trace!("Recv <<{}>>", lines.join("\n"));
        let raw_msg = RawAptMessage::parse(lines)?;
        debug!("Received Raw {:?}", raw_msg);
        let msg = AptMessage::from_raw(&raw_msg)?;
        debug!("Received {:?}", msg);
        Ok(msg)
    }

    async fn send_message(&mut self, message: AptMessage) -> Result<(), Box<dyn Error>> {
        debug!("Sending {:?}", message);
        trace!("Send <<{}>>", message.to_raw().to_string());
        self.out.write(message.to_raw().to_string().as_bytes()).await?;
        Ok(())
    }

    async fn send_status(&mut self, message: &str) -> Result<(), Box<dyn Error>> {
        self.send_message(AptMessage::Status(Status { message: message.to_string() })).await?;
        Ok(())
    }

    async fn send_uri_failure(&mut self, uri: &str, error: &str) -> Result<(), Box<dyn Error>> {
        self.send_message(AptMessage::URIFailure(URIFailure { uri: uri.to_string(), message: error.to_string() })).await?;
        Ok(())
    }

    async fn acquire_uri(&mut self, uri_acquire: &URIAcquire) -> Result<(), Box<dyn Error>> {
        self.send_status(&format!("Fetching S3 uri: {}", uri_acquire.uri)).await?;

        let s3_id = uri_acquire.uri.parse::<S3Id>()?;
        debug!("s3_id={:?}", s3_id);
        use aws_sdk_s3::SdkError;
        let head = self.s3.head_object()
            .bucket(&s3_id.bucket)
            .key(&s3_id.key)
            .send()
            .await.map_err(|e| match e {
                SdkError::ServiceError{ err: se, raw: _raw } => format!("Error downloading {}: {}", uri_acquire.uri, se.code().unwrap_or("??")),
                _ => format!("Error downloading {}: {}", uri_acquire.uri, e)
            })?;

        self.send_message(AptMessage::URIStart(URIStart {
            uri: uri_acquire.uri.clone(),
            size: head.content_length as usize,
            last_modified: head.last_modified.ok_or(format!("No last-modified on HEAD {}", uri_acquire.uri))?.to_chrono().into(), // RFC1123
            resume_point: 0,
        })).await?;

        let mut get = self.s3.get_object()
            .bucket(&s3_id.bucket)
            .key(&s3_id.key)
            .send()
            .await.map_err(|e| match e {
                SdkError::ServiceError{ err: se, raw: _raw } => format!("Error downloading {} {} {} {:?}", uri_acquire.uri, se.code().unwrap_or("??"), se.message().unwrap_or("Unknown"), se),
                _ => format!("Error downloading {}: {}", uri_acquire.uri, e)
            })?;
        use std::path::Path;

        use tempfile::NamedTempFile;
        let mut tmp_file = NamedTempFile::new_in(Path::new(&uri_acquire.filename).parent().ok_or(format!("No parent for {}", uri_acquire.filename))?)?;

        use std::io::Write;
        use sha2::Digest;
        let mut md5 = md5::Md5::new();
        let mut sha256 = sha2::Sha256::new();
        let mut sha512 = sha2::Sha512::new();

        use tokio_stream::StreamExt;
        while let Some(bytes) = get.body.try_next().await? {
            md5.write(&bytes)?;
            sha256.write(&bytes)?;
            sha512.write(&bytes)?;
            tmp_file.write(&bytes)?;
        }

        tmp_file.persist(&uri_acquire.filename)?;

        self.send_message(AptMessage::URIDone(URIDone {
            uri: uri_acquire.uri.clone(),
            size: get.content_length as usize,
            last_modified: Local::now(),
            filename: uri_acquire.filename.to_string(),
            md5_hash: md5.finalize(),
            sha256_hash: sha256.finalize(),
            sha512_hash: sha512.finalize(),
        })).await?;

        Ok(())
    }
}

#[derive(Debug)]
struct S3Id {
    pub bucket: String,
    pub key: String,
}

use std::str::FromStr;
impl FromStr for S3Id {
    type Err = Box<dyn Error>;
    fn from_str(uri_str: &str) -> Result<S3Id,Box<dyn Error>> {
        use http::Uri;
        let uri = uri_str.parse::<Uri>()?;
        if uri.scheme_str() != Some("s3") { Err(format!("Not an s3 URI: {}", uri))? }
        Ok(S3Id{
            bucket: uri.host().ok_or(format!("URL is missing the bucket: {}", uri))?.trim_end_matches(".s3.amazonaws.com").to_string(),
            key: uri.path()[1..].to_string(),
        })
    }
}
