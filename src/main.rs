extern crate rustwt;
extern crate uuid;

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use rustwt::{Algorithm, Encoder, Payload, Value, Number};
use uuid::Uuid;

fn main() {
    let secret = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    let aud = env::var("AUD").expect("AUD must be set");
    let iss = env::var("ISS").expect("ISS must be set");
    let sub = env::var("SUB").expect("SUB must be set");

    let now = SystemTime::now();
    let iat = now.duration_since(UNIX_EPOCH).expect("unstable clock");
    let exp = iat.as_secs() + 600;
    let nbf = iat.as_secs() - 1;
    let jti = Uuid::new_v4();

    let mut payload = Payload::new();

    payload.insert("aud".to_string(), Value::String(aud));
    payload.insert("exp".to_string(), Value::Number(Number::from(exp)));
    payload.insert("iat".to_string(), Value::Number(Number::from(iat.as_secs())));
    payload.insert("iss".to_string(), Value::String(iss));
    payload.insert("jti".to_string(), Value::String(jti.to_string()));
    payload.insert("nbf".to_string(), Value::Number(Number::from(nbf)));
    payload.insert("sub".to_string(), Value::String(sub));

    let encoder = Encoder::from_raw_private_key(&secret, Algorithm::HS512).unwrap();
    let jwt = encoder.encode(payload).expect("could not encode token");

    println!("{}", jwt);
}
