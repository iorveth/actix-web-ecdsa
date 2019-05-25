#[macro_use]
extern crate serde_derive;
use actix_files as fs;
use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use ring::{
    rand,
    signature::{self, KeyPair},
};
use signature::EcdsaKeyPair;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
pub struct SignParams {
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
pub struct VerifyParams {
    public_key: String,
    signed_message: String,
}

struct ECDSAState {
    //Public key - KeyPair
    keys: Mutex<HashMap<String, EcdsaKeyPair>>,
    //Signature - Message
    signatures: Mutex<HashMap<String, String>>,
}

fn main() -> std::io::Result<()> {
    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a number");
    //Shared ECDSA state
    let keys_state = Arc::new(ECDSAState {
        keys: Mutex::new(HashMap::new()),
        signatures: Mutex::new(HashMap::new()),
    });
    HttpServer::new(move || {
        let keys_state_cloned = keys_state.clone();
        App::new()
            .data(keys_state_cloned)
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::get().to(sign)))
            .service(web::resource("/generate_keys").route(web::post().to(handle_generate_keys)))
            .service(web::resource("/sign_message").route(web::post().to(handle_sign_message)))
            .service(web::resource("/verify").route(web::get().to(verify)))
            .service(web::resource("/verify_message").route(web::post().to(handle_verify_message)))
            .service(fs::Files::new("/", "static/"))
    })
    .bind(("0.0.0.0", port))?
    .run()
}

fn generate_ecdsa_key_pair() -> Result<EcdsaKeyPair, Box<std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        untrusted::Input::from(pkcs8_bytes.as_ref()),
    )?;
    Ok(key_pair)
}

fn sign_message(message: &[u8], key_pair: &EcdsaKeyPair) -> Result<String, Box<std::error::Error>> {
    let msg = untrusted::Input::from(message);
    let rng = rand::SystemRandom::new();
    let sig = key_pair.sign(&rng, msg)?;
    let sig_bytes = sig.as_ref();
    Ok(hex::encode(sig_bytes))
}

fn verify_signed_message(
    message_bytes: &[u8],
    signed_message_bytes: &[u8],
    public_ecdsa_key_bytes: &[u8],
) -> Result<(), ring::error::Unspecified> {
    let message = untrusted::Input::from(&message_bytes);
    let sig = untrusted::Input::from(&signed_message_bytes);
    let public_ecdsa_key = untrusted::Input::from(&public_ecdsa_key_bytes);
    signature::verify(
        &signature::ECDSA_P256_SHA256_ASN1,
        public_ecdsa_key,
        message,
        sig,
    )
}

fn sign() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/sign.html"))
}

fn verify() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/verify.html"))
}

fn handle_generate_keys(ecdsa_state: web::Data<Arc<ECDSAState>>) -> HttpResponse {
    let key_pair = match generate_ecdsa_key_pair() {
        Ok(key_pair) => key_pair,
        Err(_) => {
            return HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Key generation error occured!"))
        }
    };
    let public_key = key_pair.public_key();
    let public_key_str = format!("{:?}", public_key)
        .replace("PublicKey", "")
        .replace("(\"", "")
        .replace("\")", "");
    let mut keys_state = ecdsa_state.keys.lock().unwrap();
    keys_state.insert(public_key_str.clone(), key_pair);
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("Public key: {}", public_key_str))
}

fn handle_sign_message(
    ecdsa_state: web::Data<Arc<ECDSAState>>,
    params: web::Form<SignParams>,
) -> HttpResponse {
    let public_ecdsa_key = params.public_key.trim().to_string();
    let keys_state = ecdsa_state.keys.lock().unwrap();
    let mut signatures_state = ecdsa_state.signatures.lock().unwrap();
    if keys_state.contains_key(&public_ecdsa_key) {
        let key_pair = keys_state.get(&public_ecdsa_key).unwrap();
        let message = params.message.trim();
        let message_bytes = message.as_bytes();
        let sig_str = match sign_message(&message_bytes, key_pair) {
            Ok(sig_str) => sig_str,
            Err(_) => {
                return HttpResponse::Ok()
                    .content_type("text/plain")
                    .body(format!("Signature generation error occured!"))
            }
        };
        signatures_state.insert(sig_str.clone(), message.to_string());
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("Your signature is: {}", sig_str))
    } else {
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("Key-Value pair not found"))
    }
}

fn handle_verify_message(
    ecdsa_state: web::Data<Arc<ECDSAState>>,
    params: web::Form<VerifyParams>,
) -> impl Responder {
    let public_ecdsa_key = params.public_key.trim().to_string();
    let signed_message = params.signed_message.trim().to_string();
    let keys_state = ecdsa_state.keys.lock().unwrap();
    let signatures_state = ecdsa_state.signatures.lock().unwrap();

    if keys_state.contains_key(&public_ecdsa_key) && signatures_state.contains_key(&signed_message)
    {
        let message = signatures_state.get(&signed_message).unwrap();
        let message_bytes = message.as_bytes();
        let public_ecdsa_key_bytes = match hex::decode(&public_ecdsa_key) {
            Ok(public_ecdsa_key_bytes) => public_ecdsa_key_bytes,
            Err(_) => {
                return HttpResponse::Ok()
                    .content_type("text/plain")
                    .body(format!("Invalid public key format"))
            }
        };
        let signed_message_bytes = match hex::decode(&signed_message) {
            Ok(signed_message_bytes) => signed_message_bytes,
            Err(_) => {
                return HttpResponse::Ok()
                    .content_type("text/plain")
                    .body(format!("Invalid signed message format"))
            }
        };
        if let Ok(_) = verify_signed_message(
            &message_bytes,
            &signed_message_bytes,
            &public_ecdsa_key_bytes,
        ) {
            HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Verified!"))
        } else {
            HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Verification Error!"))
        }
    } else {
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("Key-Value or Signature-Message pair not found"))
    }
}
