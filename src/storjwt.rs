use crate::{Args};
use clap::Parser;
use hmac::{Hmac, Mac};
use jwt::{Header, Token, VerifyWithKey};
use sha2::Sha256;
use std::collections::BTreeMap;
use toml::value::Table;

pub fn verify_jwt_token(token_str: &str) -> Result<BTreeMap<String, String>, jwt::Error> {
    // config.toml, jwt_secret parameter
    let args = Args::parse();
    let cfg_file = args.config_file;
    let toml_cfg = std::fs::read_to_string(&cfg_file).unwrap();
    let parsed_toml = toml_cfg.parse::<Table>().unwrap();
    let key_str = parsed_toml["jwt_secret"].as_str().unwrap();
    let key: Hmac<Sha256> = Hmac::new_from_slice(key_str.as_bytes())?;
    let verify_result = token_str.verify_with_key(&key);
    let token: Token<Header, BTreeMap<String, String>, _> = match verify_result {
        Ok(token) => token,
        Err(e) => {
            println!("verify_result Error: {:?}", e);
            return Err(e);
        }
    };
    //let header = token.header();
    let claims = token.claims();
    let email = claims.get("email");
    match email {
        Some(email) => {
            println!("email: {}", email);
        }
        None => {
            println!("email not found");
            return Err(jwt::Error::InvalidSignature);
        }
    }
    Ok(claims.clone())
}
