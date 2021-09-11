// Copyright © 2021 David Caldwell <david@porkrind.org>. MIT Licensed. See LICENSE file for details.

use chrono::{DateTime,Local};

use std::error::Error;


#[derive(Debug, Clone)]
pub enum AptMessage {
    /* 100 */ Capabilities(Capabilities),
    /* 101 */ //Log(Log),
    /* 102 */ Status(Status),
    /* 200 */ URIStart(URIStart),
    /* 201 */ URIDone(URIDone),
    /* 351 */ //AuxRequest(AuxRequest),
    /* 400 */ URIFailure(URIFailure),
    /* 401 */ GeneralFailure(GeneralFailure),
    /* 402 */ //AuthorizationRequired(AuthorizationRequired),
    /* 403 */ //MediaFailure(MediaFailure),
    /* 600 */ URIAcquire(URIAcquire),
    /* 601 */ Configuration(Configuration),
    /* 602 */ //AuthorizationCredentials(AuthorizationCredentials),
    /* 603 */ //MediaChanged(MediaChanged),
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub version: String,
    pub single_instance: bool,
    pub local_only: bool,
    pub pipeline: bool,
    pub send_config: bool,
    pub needs_cleanup: bool,
    pub removable: bool,
    pub aux_requests: bool,
    pub send_uri_encode: bool
}

#[derive(Debug, Clone)]
pub struct Log {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct URIStart {
    pub uri: String,
    pub size: usize,
    pub last_modified: DateTime<Local>, // RFC1123
    pub resume_point: usize,
}

#[derive(Debug, Clone)]
pub struct URIDone {
    pub uri: String,
    pub size: usize,
    pub last_modified: DateTime<Local>,
    pub filename: String,
    pub md5_hash: generic_array::GenericArray<u8, generic_array::typenum::U16>,
    pub sha256_hash: generic_array::GenericArray<u8, generic_array::typenum::U32>,
    pub sha512_hash: generic_array::GenericArray<u8, generic_array::typenum::U64>,
}

#[derive(Debug, Clone)]
pub struct AuxRequest {
    pub uri: String /* URI of the file causing the need for the auxiliary file */,
    pub maximum_size: usize,
    pub aux_short_desc: String,
    pub aux_description: String,
    pub aux_uri: String,
}

#[derive(Debug, Clone)]
pub struct URIFailure {
    pub uri: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct GeneralFailure {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequired {
    pub site: String,
}

#[derive(Debug, Clone)]
pub struct MediaFailure {
    pub media: String,
    pub drive: String,
}

#[derive(Debug, Clone)]
pub struct URIAcquire {
    pub uri: String,
    pub filename: String,
    pub last_modified: Option<DateTime<Local>>,
}

#[derive(Debug, Clone)]
pub struct Configuration {
    pub config_items: Vec<ConfigItem>
}

#[derive(Debug, Clone)]
pub struct ConfigItem {
    pub item: String,
    pub value: String,
}

impl ConfigItem {
    pub fn parse(s: &str) -> Result<ConfigItem, Box<dyn Error>> {
        let (k,v) = s.split_once('=').ok_or(format!("Badly formated Conf-Item: {}", s))?;
        Ok(ConfigItem { item: k.to_string(), value: v.to_string() })
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationCredentials {
    pub site: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct MediaChanged {
    pub media: String,
    pub fail: bool,
}

pub trait FromRaw<T> {
    fn from_raw(msg: &RawAptMessage) -> Result<T, Box<dyn Error>>;
}

impl FromRaw<AptMessage> for AptMessage {
    fn from_raw(msg: &RawAptMessage) -> Result<AptMessage, Box<dyn Error>> {
        match msg.code {
            100 => Ok(AptMessage::Capabilities(Capabilities::from_raw(msg)?)),
            // 101 => Ok(AptMessage::Log(Log::from_raw(msg)?)),
            // 102 => Ok(AptMessage::Status(Status::from_raw(msg)?)),
            // 200 => Ok(AptMessage::URIStart(URIStart::from_raw(msg)?)),
            // 201 => Ok(AptMessage::URIDone(URIDone::from_raw(msg)?)),
            // 351 => Ok(AptMessage::AuxRequest(AuxRequest::from_raw(msg)?)),
            // 400 => Ok(AptMessage::URIFailure(URIFailure::from_raw(msg)?)),
            // 401 => Ok(AptMessage::GeneralFailure(GeneralFailure::from_raw(msg)?)),
            // 402 => Ok(AptMessage::AuthorizationRequired(AuthorizationRequired::from_raw(msg)?)),
            // 403 => Ok(AptMessage::MediaFailure(MediaFailure::from_raw(msg)?)),
            600 => Ok(AptMessage::URIAcquire(URIAcquire::from_raw(msg)?)),
            601 => Ok(AptMessage::Configuration(Configuration::from_raw(msg)?)),
            // 602 => Ok(AptMessage::AuthorizationCredentials(AuthorizationCredentials::from_raw(msg)?)),
            // 603 => Ok(AptMessage::MediaChanged(MediaChanged::from_raw(msg)?)),
            _ => Err(format!("Unimplemented: {:?}", msg))?,
        }
    }
}


pub trait ToRaw {
    fn to_raw(&self) -> RawAptMessage;
}

impl ToRaw for AptMessage {
    fn to_raw(&self) -> RawAptMessage {
        match self {
            AptMessage::Capabilities(it)             => it.to_raw(),  /* 100 */
            //AptMessage::Log(it)                      => it.to_raw(),  /* 101 */
            AptMessage::Status(it)                   => it.to_raw(),  /* 102 */
            AptMessage::URIStart(it)                 => it.to_raw(),  /* 200 */
            AptMessage::URIDone(it)                  => it.to_raw(),  /* 201 */
            // AptMessage::AuxRequest(it)               => it.to_raw(),  /* 351 */
            AptMessage::URIFailure(it)               => it.to_raw(),  /* 400 */
            // AptMessage::GeneralFailure(it)           => it.to_raw(),  /* 401 */
            // AptMessage::AuthorizationRequired(it)    => it.to_raw(),  /* 402 */
            // AptMessage::MediaFailure(it)             => it.to_raw(),  /* 403 */
            // AptMessage::URIAcquire(it)               => it.to_raw(),  /* 600 */
            // AptMessage::Configuration(it)            => it.to_raw(),  /* 601 */
            // AptMessage::AuthorizationCredentials(it) => it.to_raw(),  /* 602 */
            // AptMessage::MediaChanged(it)             => it.to_raw(),  /* 603 */
            _ => RawAptMessage::new(500, &format!("Unimplemented: {:?}", self)),
        }
    }
}

fn maybe(v: bool) -> Option<bool> {
    match v {
        true => Some(true),
        false => None,
    }
}

impl ToRaw for Capabilities {
    fn to_raw(&self) -> RawAptMessage {
         RawAptMessage::new(100, "Capabilities")
            .add_header("Version",        Some(&self.version))
            .add_header("SingleInstance", maybe(self.single_instance))
            .add_header("LocalOnly",      maybe(self.local_only     ))
            .add_header("Pipeline",       maybe(self.pipeline       ))
            .add_header("SendConfig",     maybe(self.send_config    ))
            .add_header("NeedsCleanup",   maybe(self.needs_cleanup  ))
            .add_header("Removable",      maybe(self.removable      ))
            .add_header("AuxRequests",    maybe(self.aux_requests   ))
            .add_header("SendUriEncode",  maybe(self.send_uri_encode))
    }
}

impl FromRaw<Capabilities> for Capabilities {
    fn from_raw(msg: &RawAptMessage) -> Result<Capabilities, Box<dyn Error>> {
        Ok(Capabilities {
            version         : msg.string_header("Version")?,
            single_instance : msg.bool_header("SingleInstance")?,
            local_only      : msg.bool_header("LocalOnly"     )?,
            pipeline        : msg.bool_header("Pipeline"      )?,
            send_config     : msg.bool_header("SendConfig"    )?,
            needs_cleanup   : msg.bool_header("NeedsCleanup"  )?,
            removable       : msg.bool_header("Removable"     )?,
            aux_requests    : msg.bool_header("AuxRequests"   )?,
            send_uri_encode : msg.bool_header("SendUriEncode" )?,
        })
    }
}

impl ToRaw for Log {
    fn to_raw(&self) -> RawAptMessage {
        RawAptMessage::new(101, "Log")
            .add_header("Message", Some(&self.message))
    }
}

impl ToRaw for Status {
    fn to_raw(&self) -> RawAptMessage {
        RawAptMessage::new(102, "Status")
            .add_header("Message", Some(&self.message))
    }
}

impl ToRaw for URIStart {
    fn to_raw(&self) -> RawAptMessage {
        RawAptMessage::new(200, "URI Start")
            .add_header("URI", Some(&self.uri))
            .add_header("Size", Some(self.size))
            .add_header("Last-Modifed", Some(self.last_modified))
            .add_header("Resume-Point", Some(self.resume_point))
    }
}

impl ToRaw for URIDone {
    fn to_raw(&self) -> RawAptMessage {
        RawAptMessage::new(201, "URI Done")
            .add_header("URI", Some(&self.uri))
            .add_header("Size", Some(self.size))
            .add_header("Last-Modifed", Some(self.last_modified))
            .add_header("Filename", Some(self.filename.clone()))
            .add_header("MD5-Hash",    Some(format!("{:x}", self.md5_hash)))
            .add_header("MD5Sum-Hash", Some(format!("{:x}", self.md5_hash)))
            .add_header("SHA256-Hash", Some(format!("{:x}", self.sha256_hash)))
            .add_header("SHA512-Hash", Some(format!("{:x}", self.sha512_hash)))
    }
}

impl ToRaw for URIFailure {
    fn to_raw(&self) -> RawAptMessage {
        RawAptMessage::new(400, "URI Failure")
            .add_header("URI", Some(&self.uri))
            .add_header("Message", Some(&self.message))
    }
}

impl FromRaw<URIAcquire> for URIAcquire {
    fn from_raw(msg: &RawAptMessage) -> Result<URIAcquire, Box<dyn Error>> {
        let last_modified = msg.optional_string_header("Last-Modified");
        Ok(URIAcquire{
            uri: msg.string_header("URI")?,
            filename: msg.string_header("Filename")?,
            last_modified: last_modified.map(|lm| DateTime::<chrono::FixedOffset>::parse_from_rfc2822(&lm).map_err(|e|format!("Bad time in Last-Modified header: '{}': {}", lm, e))).transpose()?.map(|lm|lm.into()),
        })
    }
}

impl FromRaw<Configuration> for Configuration {
    fn from_raw(msg: &RawAptMessage) -> Result<Configuration, Box<dyn Error>> {
        Ok(Configuration {
            config_items: msg.all_values("Conf-Item").map(|conf_item| ConfigItem::parse(&conf_item)).collect::<Result<Vec<ConfigItem>, Box<dyn Error>>>()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RawAptMessage {
    code: u16,
    message: String,
    headers: Vec<(String,String)>,
}

impl RawAptMessage {
    pub fn new(code: u16, message: &str) -> RawAptMessage {
        RawAptMessage { code, message: message.to_owned(), headers: vec![] }
    }
    pub fn add_header<T: std::fmt::Display>(mut self, key: &str, value: Option<T>) -> RawAptMessage {
        match value {
            Some(v) => { self.headers.push((key.to_string(), v.to_string())) },
            _ => {}
        }
        self
    }
    pub fn to_string(&self) -> String {
        format!("{:3} {}\n{}\n", self.code, self.message, self.headers.iter().map(|(k,v)| format!("{}: {}\n", k, v)).collect::<Vec<String>>().join(""))
    }
    pub fn parse(lines: Vec<String>) -> Result<RawAptMessage, Box<dyn Error>> {
        let mut line_iter = lines.iter();
        let msg_line = line_iter.next().ok_or(format!("Message too short"))?;
        let code = msg_line[0..3].to_string().parse::<u16>()?;
        let mut msg = RawAptMessage::new(code, &msg_line[4..]);
        for line in line_iter {
            if let Some((k,v)) = line.split_once(':') {
                msg = msg.add_header(k.trim(),Some(v.trim()));
            } else {
                Err(format!("Bad header line: {}", line.trim_end()))?;
            }
        }
        Ok(msg)
    }

    pub fn string_header(&self, key: &str) -> Result<String, Box<dyn Error>> {
        Ok(self.headers.iter().find(|(k,_)| k == key).ok_or(format!("Missing header: {}", key))?.1.clone())
    }
    pub fn optional_string_header(&self, key: &str) -> Option<String> {
        self.headers.iter().find(|(k,_)| k == key).map(|(_,v)| v.clone())
    }
    pub fn bool_header(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let bool_str = self.headers.iter().find(|(k,_)| k == key).unwrap_or(&("".to_string(),"false".to_string())).1.clone();
        Ok(bool_str.parse::<bool>().map_err(|e|format!("Error parsing bool header {}: {}: {}", key, bool_str, e))?)
    }
    pub fn all_values<'a>(&'a self, key: &'a str) -> Box<dyn Iterator<Item = &'a String> + 'a> {
        Box::new(self.headers.iter().filter(move |(k,_)| k==key).map(|(_,v)|v))
    }
}

