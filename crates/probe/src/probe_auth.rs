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
        &canonical_origin_path_and_query(url)?,
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
    canonical_origin_path_and_query: &str,
    timestamp_ms: &str,
    nonce: &str,
    body_sha256: &str,
) -> String {
    [
        method.to_ascii_uppercase(),
        canonical_origin_path_and_query.to_string(),
        timestamp_ms.to_string(),
        nonce.to_string(),
        body_sha256.to_string(),
    ]
    .join("\n")
}

fn canonical_origin_path_and_query(url: &str) -> Result<String, String> {
    let url = url::Url::parse(url).map_err(|error| error.to_string())?;
    url.host_str()
        .ok_or_else(|| "request URL is missing host".to_string())?;
    let mut canonical = url.origin().ascii_serialization();
    canonical.push_str(url.path());
    if let Some(query) = url.query() {
        canonical.push('?');
        canonical.push_str(query);
    }

    Ok(canonical)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        RsaPublicKey,
        pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey},
        pkcs8::EncodePrivateKey,
        signature::Verifier,
    };

    #[test]
    fn signed_probe_request_headers_bind_signature_to_canonical_origin() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
        let public_key = RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .expect("private key pem")
            .to_string();
        let auth = ProbeRequestAuth {
            probe_id: "probe_01",
            probe_private_key_pem: &private_key_pem,
            server_time_offset_ms: 0,
        };

        let headers = signed_probe_request_headers(
            "post",
            "https://hub.example:8443/base/api/probe/report?cursor=1",
            &auth,
            b"report-body",
        )
        .expect("headers");
        let header = |name: &str| {
            headers
                .iter()
                .find_map(|(candidate, value)| (*candidate == name).then_some(value.as_str()))
                .expect("header")
        };
        let payload = probe_request_signature_payload(
            "post",
            "https://hub.example:8443/base/api/probe/report?cursor=1",
            header("x-enoki-timestamp-ms"),
            header("x-enoki-nonce"),
            header("x-enoki-body-sha256"),
        );
        let signature = RsaPkcs1v15Signature::try_from(
            hex_decode(header("x-enoki-signature"))
                .expect("signature hex")
                .as_slice(),
        )
        .expect("signature");

        VerifyingKey::<Sha256>::new(public_key)
            .verify(payload.as_bytes(), &signature)
            .expect("signature verifies with canonical origin payload");
    }

    #[test]
    fn canonical_origin_path_and_query_preserves_ipv6_brackets() {
        assert_eq!(
            canonical_origin_path_and_query("http://[::1]:3001/api/probe/report?cursor=1"),
            Ok("http://[::1]:3001/api/probe/report?cursor=1".to_string()),
        );
    }

    fn hex_decode(value: &str) -> Option<Vec<u8>> {
        if !value.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for index in (0..value.len()).step_by(2) {
            bytes.push(u8::from_str_radix(&value[index..index + 2], 16).ok()?);
        }

        Some(bytes)
    }
}
