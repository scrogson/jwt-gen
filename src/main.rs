extern crate rustwt;
#[macro_use]
extern crate structopt;
extern crate uuid;

use std::time::{SystemTime, UNIX_EPOCH};

use rustwt::{Algorithm, Encoder, Payload, Value, Number};
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
            parse(from_str = "parse_alg"),
            raw(possible_values = r#"&[
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512"
            ]"#)
        )]
        /// JWT algorithm.
        alg: Algorithm,

        #[structopt(long = "aud", short = "a", env = "AUD")]
        aud: Option<String>,

        #[structopt(long = "iss", short = "i", env = "ISS")]
        iss: Option<String>,

        #[structopt(long = "key", short = "k", env = "KEY")]
        key: String,

        #[structopt(long = "sub", short = "s", env = "SUB")]
        sub: Option<String>,
    },

    #[structopt(name = "decode")]
    Decode {
    }
}

fn parse_alg(alg: &str) -> Algorithm {
    match alg {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "ES512" => Algorithm::ES512,
        _ => unreachable!(),
    }
}

fn main() {
    match Options::from_args() {
        Options::Encode { alg, aud, iss, key, sub, .. } => {
            let now = SystemTime::now();
            let iat = now.duration_since(UNIX_EPOCH).expect("unstable clock");
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

            let encoder = Encoder::from_raw_private_key(&key, alg).unwrap();
            let jwt = encoder.encode(payload).expect("could not encode token");

            println!("{}", jwt);
        },
        Options::Decode { .. } => {
            println!("not yet implemented");
        },
    };

}
