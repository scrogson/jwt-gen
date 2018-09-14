extern crate failure;
extern crate rustwt;
#[macro_use]
extern crate structopt;
extern crate uuid;

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use failure::Error;
use rustwt::{Algorithm, Decoder, Encoder, Payload, Value, Number};
use Algorithm::*;
use structopt::StructOpt;
use uuid::Uuid;

#[derive(Debug, StructOpt)]
#[structopt(name = "jwt")]
enum Options {
    #[structopt(name = "encode")]
    Encode {
        #[structopt(
            long = "alg",
            short = "A",
            env = "ALG",
            default_value = "HS512",
            parse(from_str = "parse_algorithm"),
            raw(
                possible_values = r#"&[
                    "HS256",
                    "HS384",
                    "HS512",
                    "RS256",
                    "RS384",
                    "RS512",
                    "ES256",
                    "ES384",
                    "ES512",
                ]"#,
            )
        )]
        /// JWT algorithm.
        alg: Algorithm,

        #[structopt(long = "aud", short = "a", env = "AUD")]
        /// Audience claim
        aud: Option<String>,

        #[structopt(long = "iss", short = "i", env = "ISS")]
        /// Issuer claim
        iss: Option<String>,

        #[structopt(long = "key", short = "k", env = "KEY")]
        /// The secret key which is used to sign the token.
        ///
        /// In the case for HMAC based tokens, this should be a raw secret.
        /// In the case for RS/EC algorithms, a file path to the private key
        /// is expected.
        key: String,

        #[structopt(long = "sub", short = "s", env = "SUB")]
        /// Subject claim
        sub: Option<String>,
    },

    #[structopt(name = "decode")]
    Decode {
        #[structopt(long = "key", short = "k", env = "KEY")]
        /// The secret key which is used to sign the token.
        ///
        /// In the case for HMAC based tokens, this should be a raw secret.
        /// In the case for RS/EC algorithms, a file path to the private key
        /// is expected.
        key: String,

        token: String,
    }
}

fn parse_algorithm(algorithm: &str) -> Algorithm {
    match algorithm {
        "HS256" => HS256,
        "HS384" => HS384,
        "HS512" => HS512,
        "RS256" => RS256,
        "RS384" => RS384,
        "RS512" => RS512,
        "ES256" => ES256,
        "ES384" => ES384,
        "ES512" => ES512,
        _ => unreachable!(),
    }
}

trait AlgorithmExt {
    fn requires_file_path(self) -> bool;
}

impl AlgorithmExt for Algorithm {
    fn requires_file_path(self) -> bool {
        match self {
            HS256 | HS384 | HS512 => false,
            _ => true
        }
    }
}

fn main() -> Result<(), Error> {
    match Options::from_args() {
        Options::Encode { alg, aud, iss, key, sub, .. } => {
            let now = SystemTime::now();
            let iat = now.duration_since(UNIX_EPOCH)?;
            let exp = iat.as_secs() + 600;
            let nbf = iat.as_secs() - 1;
            let jti = Uuid::new_v4();

            let mut payload = Payload::new();

            aud.and_then(|aud| payload.insert("aud".to_string(), Value::String(aud)));
            iss.and_then(|iss| payload.insert("iss".to_string(), Value::String(iss)));
            sub.and_then(|sub| payload.insert("sub".to_string(), Value::String(sub)));

            payload.insert("exp".to_string(), Value::Number(Number::from(exp)));
            payload.insert("iat".to_string(), Value::Number(Number::from(iat.as_secs())));
            payload.insert("jti".to_string(), Value::String(jti.to_string()));
            payload.insert("nbf".to_string(), Value::Number(Number::from(nbf)));

            let key = fs::canonicalize(&key)
                .and_then(|path| fs::read_to_string(path))
                .unwrap_or(key);

            let encoder = Encoder::from_raw_private_key(&key, alg)?;
            let token = encoder.encode(payload)?;

            println!("{}", token);
        },

        Options::Decode { key, token } => {
            let decoder = match fs::canonicalize(&key) {
                Ok(path) => {
                    match fs::read_to_string(path) {
                        Ok(contents) => Decoder::from_pem(&contents),
                        Err(_) => Err(rustwt::Error::JWTInvalid)
                    }
                },
                Err(_) => Decoder::from_hmac_secret(&key)
            }?;

            let (_header, payload) = decoder.decode(token)?;

            println!("{:#?}", payload);
        },
    };

    Ok(())
}
