use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    rand_core::{OsRng, RngCore},
    signature::{RandomizedSigner, SignatureEncoding},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct ProbeRequestAuth<'a> {
    pub probe_id: &'a str,
    pub probe_private_key_pem: &'a str,
    pub server_time_offset_ms: i64,
}

pub fn signed_probe_request_headers(
    method: &str,
    url: &str,
    auth: &ProbeRequestAuth<'_>,
    body: &[u8],
) -> Result<Vec<(&'static str, String)>, String> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(auth.probe_private_key_pem)
        .map_err(|error| error.to_string())?;
    let timestamp_ms = current_unix_time_ms(auth.server_time_offset_ms);
    let nonce = random_hex(16);
    let body_sha256 = hex_encode(&Sha256::digest(body));
    let payload = probe_request_signature_payload(
        method,
        &request_path_and_query(url),
        &timestamp_ms,
        &nonce,
        &body_sha256,
    );
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut OsRng, payload.as_bytes());

    Ok(vec![
        ("x-enoki-probe-id", auth.probe_id.to_string()),
        ("x-enoki-timestamp-ms", timestamp_ms),
        ("x-enoki-nonce", nonce),
        ("x-enoki-body-sha256", body_sha256),
        (
            "x-enoki-signature",
            hex_encode(signature.to_bytes().as_ref()),
        ),
    ])
}

fn probe_request_signature_payload(
    method: &str,
    path_and_query: &str,
    timestamp_ms: &str,
    nonce: &str,
    body_sha256: &str,
) -> String {
    [
        method.to_ascii_uppercase(),
        path_and_query.to_string(),
        timestamp_ms.to_string(),
        nonce.to_string(),
        body_sha256.to_string(),
    ]
    .join("\n")
}

fn request_path_and_query(url: &str) -> String {
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return url.to_string();
    };
    let Some(path_start) = after_scheme.find('/') else {
        return "/".to_string();
    };

    after_scheme[path_start..].to_string()
}

fn current_unix_time_ms(server_time_offset_ms: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    (now.as_millis() as i128 + server_time_offset_ms as i128).to_string()
}

fn random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0; byte_count];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
