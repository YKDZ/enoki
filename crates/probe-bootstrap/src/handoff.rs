//! The one-way, component-only stdin protocol between unprivileged acquisition
//! and root activation. No compressed archive crosses this boundary.
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const MAGIC: [u8; 8] = *b"ENKBH008";
pub const SCHEMA_VERSION: u16 = 8;
pub const MAX_COMPONENT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 256 * 1024;
pub const MAX_ENROLLMENT_BYTES: usize = 8 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum HandoffError {
    InvalidEnrollment,
    InvalidHeader,
    InvalidSection,
    Io,
    MissingSection,
    TooLarge,
}

/// The caller's bounded enrollment capability. It never participates in
/// distribution trust, asset selection, or component verification.
#[derive(Eq, PartialEq, Zeroize)]
pub struct Enrollment {
    hub_origin: String,
    enrollment_token: String,
    lifecycle_authority_public_key: Option<Vec<u8>>,
}

impl Enrollment {
    pub fn new(hub_origin: &str, enrollment_token: &str) -> Result<Self, HandoffError> {
        let hub_origin = normalize_hub_origin(hub_origin).ok_or(HandoffError::InvalidEnrollment)?;
        if !is_enrollment_token(enrollment_token) {
            return Err(HandoffError::InvalidEnrollment);
        }
        Ok(Self {
            hub_origin,
            enrollment_token: enrollment_token.to_owned(),
            lifecycle_authority_public_key: None,
        })
    }

    pub fn hub_origin(&self) -> &str {
        &self.hub_origin
    }
    pub fn enrollment_token(&self) -> &str {
        &self.enrollment_token
    }
    pub(crate) fn bind_lifecycle_authority_public_key(&mut self, key: Vec<u8>) {
        self.lifecycle_authority_public_key = Some(key);
    }
    pub(crate) fn lifecycle_authority_public_key(&self) -> Option<&[u8]> {
        self.lifecycle_authority_public_key.as_deref()
    }

    fn encode(&self) -> Result<Vec<u8>, HandoffError> {
        let value = EnrollmentWire {
            hub_origin: &self.hub_origin,
            enrollment_token: &self.enrollment_token,
        };
        let bytes = serde_json::to_vec(&value).map_err(|_| HandoffError::InvalidEnrollment)?;
        if bytes.len() > MAX_ENROLLMENT_BYTES || bytes != canonical_enrollment_json(&value) {
            return Err(HandoffError::InvalidEnrollment);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandoffError> {
        if bytes.is_empty() || bytes.len() > MAX_ENROLLMENT_BYTES {
            return Err(HandoffError::TooLarge);
        }
        let value: EnrollmentOwnedWire =
            serde_json::from_slice(bytes).map_err(|_| HandoffError::InvalidEnrollment)?;
        let parsed = Enrollment::new(&value.hub_origin, &value.enrollment_token)?;
        let canonical = parsed.encode()?;
        if bytes != canonical {
            return Err(HandoffError::InvalidEnrollment);
        }
        Ok(parsed)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentWire<'a> {
    hub_origin: &'a str,
    enrollment_token: &'a str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentOwnedWire {
    hub_origin: String,
    enrollment_token: String,
}
fn canonical_enrollment_json(value: &EnrollmentWire<'_>) -> Vec<u8> {
    // serde struct field order is the exact wire order; no trailing newline.
    serde_json::to_vec(value).expect("bounded enrollment serialization")
}

/// Exact normalized HTTP(S) origin accepted by both roles without a URL
/// parsing dependency in the privileged binary.
pub fn normalize_hub_origin(value: &str) -> Option<String> {
    if value.len() > 2048
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let (scheme, authority) = if let Some(rest) = value.strip_prefix("https://") {
        ("https", rest)
    } else {
        ("http", value.strip_prefix("http://")?)
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', '\\']) {
        return None;
    }
    validate_authority(authority)?;
    Some(format!("{scheme}://{authority}"))
}
fn validate_authority(authority: &str) -> Option<()> {
    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']')?;
        let address = &rest[..closing];
        address.parse::<std::net::Ipv6Addr>().ok()?;
        let after = &rest[closing + 1..];
        if !after.is_empty() {
            validate_port(after.strip_prefix(':')?)?;
        }
        return Some(());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return None;
            }
            (host, Some(port))
        }
        None => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_err() && !valid_dns_name(host) {
        return None;
    }
    if let Some(port) = port {
        validate_port(port)?;
    }
    Some(())
}
fn validate_port(port: &str) -> Option<()> {
    (!port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().ok()? != 0)
        .then_some(())
}
fn valid_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
fn is_enrollment_token(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("enk_enroll_") else {
        return false;
    };
    (1..=128).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Untrusted but bounded verification inputs. Root obtains its distribution
/// root from its build-fixed policy, never from this protocol.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Handoff {
    pub delegation: Vec<u8>,
    pub delegation_signature: Vec<u8>,
    pub manifest: Vec<u8>,
    pub manifest_signature: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub bundle_manifest: Vec<u8>,
    pub lifecycle_authority_public_key: Vec<u8>,
}

impl Handoff {
    // Each fixed role carries its own authenticated length; keeping the
    // ordered fields explicit prevents a caller-supplied role collection.
    #[allow(clippy::too_many_arguments)]
    pub fn write_from(
        &self,
        enrollment: &Enrollment,
        component: &mut impl Read,
        component_len: u64,
        runtime: &mut impl Read,
        runtime_len: u64,
        cpu_provider: &mut impl Read,
        cpu_provider_len: u64,
        disk_health_provider: &mut impl Read,
        disk_health_provider_len: u64,
        lifecycle_companion: &mut impl Read,
        lifecycle_companion_len: u64,
        acquirer: &mut impl Read,
        acquirer_len: u64,
        output: &mut impl Write,
    ) -> Result<(), HandoffError> {
        if component_len == 0
            || component_len > MAX_COMPONENT_BYTES as u64
            || runtime_len == 0
            || runtime_len > MAX_COMPONENT_BYTES as u64
            || cpu_provider_len == 0
            || cpu_provider_len > MAX_COMPONENT_BYTES as u64
            || disk_health_provider_len == 0
            || disk_health_provider_len > MAX_COMPONENT_BYTES as u64
            || lifecycle_companion_len == 0
            || lifecycle_companion_len > MAX_COMPONENT_BYTES as u64
            || acquirer_len == 0
            || acquirer_len > MAX_COMPONENT_BYTES as u64
        {
            return Err(HandoffError::TooLarge);
        }
        output.write_all(&MAGIC).map_err(|_| HandoffError::Io)?;
        output
            .write_all(&SCHEMA_VERSION.to_be_bytes())
            .map_err(|_| HandoffError::Io)?;
        output.write_all(&[14, 0]).map_err(|_| HandoffError::Io)?;
        for (kind, value) in [
            (1, &self.delegation),
            (2, &self.delegation_signature),
            (3, &self.manifest),
            (4, &self.manifest_signature),
            (5, &self.signing_key),
            (6, &self.bundle_manifest),
            (7, &self.lifecycle_authority_public_key),
        ] {
            write_value(output, kind, value, MAX_METADATA_BYTES)?;
        }
        let enrollment = enrollment.encode()?;
        write_value(output, 8, &enrollment, MAX_ENROLLMENT_BYTES)?;
        write_prefix(output, 9, component_len as usize)?;
        stream_exact(component, output, component_len as usize)?;
        write_prefix(output, 10, runtime_len as usize)?;
        stream_exact(runtime, output, runtime_len as usize)?;
        write_prefix(output, 11, cpu_provider_len as usize)?;
        stream_exact(cpu_provider, output, cpu_provider_len as usize)?;
        write_prefix(output, 12, disk_health_provider_len as usize)?;
        stream_exact(
            disk_health_provider,
            output,
            disk_health_provider_len as usize,
        )?;
        write_prefix(output, 13, lifecycle_companion_len as usize)?;
        stream_exact(
            lifecycle_companion,
            output,
            lifecycle_companion_len as usize,
        )?;
        write_prefix(output, 14, acquirer_len as usize)?;
        stream_exact(acquirer, output, acquirer_len as usize)
    }

    pub fn read_metadata(input: &mut impl Read) -> Result<Self, HandoffError> {
        let mut header = [0_u8; 12];
        read_exact(input, &mut header)?;
        if header[..8] != MAGIC
            || u16::from_be_bytes([header[8], header[9]]) != SCHEMA_VERSION
            || header[10] != 14
            || header[11] != 0
        {
            return Err(HandoffError::InvalidHeader);
        }
        let mut values: [Option<Vec<u8>>; 7] = std::array::from_fn(|_| None);
        for expected in 1_u8..=7 {
            let (kind, length) = read_prefix(input)?;
            if kind != expected || length == 0 {
                return Err(HandoffError::InvalidSection);
            }
            if length > MAX_METADATA_BYTES {
                return Err(HandoffError::TooLarge);
            }
            let mut value = vec![0; length];
            read_exact(input, &mut value)?;
            values[(kind - 1) as usize] = Some(value);
        }
        let mut values = values.into_iter();
        Ok(Self {
            delegation: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            delegation_signature: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            manifest: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            manifest_signature: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            signing_key: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            bundle_manifest: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
            lifecycle_authority_public_key: values
                .next()
                .flatten()
                .ok_or(HandoffError::MissingSection)?,
        })
    }

    /// Must be called only after signed metadata and the root-owned rollback
    /// floor are verified/persisted. It consumes no component byte.
    pub fn read_enrollment(input: &mut impl Read) -> Result<Enrollment, HandoffError> {
        let (kind, length) = read_prefix(input)?;
        if kind != 8 || length == 0 {
            return Err(HandoffError::InvalidSection);
        }
        if length > MAX_ENROLLMENT_BYTES {
            return Err(HandoffError::TooLarge);
        }
        let mut bytes = vec![0; length];
        read_exact(input, &mut bytes)?;
        Enrollment::decode(&bytes)
    }
    pub fn read_component_into(
        input: &mut impl Read,
        component_sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        if expected_len == 0 || expected_len > MAX_COMPONENT_BYTES as u64 {
            return Err(HandoffError::TooLarge);
        }
        let (kind, length) = read_prefix(input)?;
        if kind != 9 || length as u64 != expected_len {
            return Err(HandoffError::InvalidSection);
        }
        stream_exact(input, component_sink, length)
    }

    pub fn read_acquirer_into(
        input: &mut impl Read,
        acquirer_sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        if expected_len == 0 || expected_len > MAX_COMPONENT_BYTES as u64 {
            return Err(HandoffError::TooLarge);
        }
        let (kind, length) = read_prefix(input)?;
        if kind != 14 || length as u64 != expected_len {
            return Err(HandoffError::InvalidSection);
        }
        stream_exact(input, acquirer_sink, length)?;
        let mut extra = [0; 1];
        match input.read(&mut extra) {
            Ok(0) => Ok(()),
            Ok(_) => Err(HandoffError::InvalidSection),
            Err(_) => Err(HandoffError::Io),
        }
    }

    pub fn read_runtime_into(
        input: &mut impl Read,
        sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        read_role_into(input, sink, expected_len, 10)
    }

    pub fn read_cpu_provider_into(
        input: &mut impl Read,
        sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        read_role_into(input, sink, expected_len, 11)
    }

    pub fn read_disk_health_provider_into(
        input: &mut impl Read,
        sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        read_role_into(input, sink, expected_len, 12)
    }

    pub fn read_lifecycle_companion_into(
        input: &mut impl Read,
        sink: &mut impl Write,
        expected_len: u64,
    ) -> Result<(), HandoffError> {
        read_role_into(input, sink, expected_len, 13)
    }
}
fn read_role_into(
    input: &mut impl Read,
    sink: &mut impl Write,
    expected_len: u64,
    expected_kind: u8,
) -> Result<(), HandoffError> {
    if expected_len == 0 || expected_len > MAX_COMPONENT_BYTES as u64 {
        return Err(HandoffError::TooLarge);
    }
    let (kind, length) = read_prefix(input)?;
    if kind != expected_kind || length as u64 != expected_len {
        return Err(HandoffError::InvalidSection);
    }
    stream_exact(input, sink, length)
}
fn write_value(
    output: &mut impl Write,
    kind: u8,
    value: &[u8],
    maximum: usize,
) -> Result<(), HandoffError> {
    if value.is_empty() || value.len() > maximum {
        return Err(HandoffError::TooLarge);
    }
    write_prefix(output, kind, value.len())?;
    output.write_all(value).map_err(|_| HandoffError::Io)
}
fn write_prefix(output: &mut impl Write, kind: u8, length: usize) -> Result<(), HandoffError> {
    let length: u32 = length.try_into().map_err(|_| HandoffError::TooLarge)?;
    output
        .write_all(&[kind])
        .and_then(|_| output.write_all(&length.to_be_bytes()))
        .map_err(|_| HandoffError::Io)
}
fn read_prefix(input: &mut impl Read) -> Result<(u8, usize), HandoffError> {
    let mut prefix = [0; 5];
    read_exact(input, &mut prefix)?;
    Ok((
        prefix[0],
        u32::from_be_bytes(prefix[1..5].try_into().expect("fixed")) as usize,
    ))
}
fn read_exact(input: &mut impl Read, output: &mut [u8]) -> Result<(), HandoffError> {
    input.read_exact(output).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            HandoffError::InvalidSection
        } else {
            HandoffError::Io
        }
    })
}
fn stream_exact(
    input: &mut impl Read,
    output: &mut impl Write,
    length: usize,
) -> Result<(), HandoffError> {
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        read_exact(input, &mut buffer[..take])?;
        output
            .write_all(&buffer[..take])
            .map_err(|_| HandoffError::Io)?;
        remaining -= take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn handoff() -> Handoff {
        Handoff {
            delegation: b"d".to_vec(),
            delegation_signature: b"ds".to_vec(),
            manifest: b"m".to_vec(),
            manifest_signature: b"ms".to_vec(),
            signing_key: b"k".to_vec(),
            bundle_manifest: b"b".to_vec(),
            lifecycle_authority_public_key: b"public-key".to_vec(),
        }
    }
    fn enrollment() -> Enrollment {
        Enrollment::new("https://hub.example", "enk_enroll_test-1").unwrap()
    }
    #[test]
    fn round_trips_ordered_handoff_after_metadata_authentication() {
        let mut encoded = Vec::new();
        handoff()
            .write_from(
                &enrollment(),
                &mut &b"abc"[..],
                3,
                &mut &b"run"[..],
                3,
                &mut &b"cpu"[..],
                3,
                &mut &b"dsk"[..],
                3,
                &mut &b"lif"[..],
                3,
                &mut &b"def"[..],
                3,
                &mut encoded,
            )
            .unwrap();
        let mut input = encoded.as_slice();
        assert_eq!(Handoff::read_metadata(&mut input).unwrap(), handoff());
        assert_eq!(
            Handoff::read_enrollment(&mut input).unwrap().hub_origin(),
            "https://hub.example"
        );
        let mut component = Vec::new();
        Handoff::read_component_into(&mut input, &mut component, 3).unwrap();
        Handoff::read_runtime_into(&mut input, &mut Vec::new(), 3).unwrap();
        Handoff::read_cpu_provider_into(&mut input, &mut Vec::new(), 3).unwrap();
        Handoff::read_disk_health_provider_into(&mut input, &mut Vec::new(), 3).unwrap();
        Handoff::read_lifecycle_companion_into(&mut input, &mut Vec::new(), 3).unwrap();
        let mut acquirer = Vec::new();
        Handoff::read_acquirer_into(&mut input, &mut acquirer, 3).unwrap();
        assert_eq!(component, b"abc");
        assert_eq!(acquirer, b"def")
    }
    #[test]
    fn rejects_secret_before_component_for_noncanonical_token_origin_and_trailing_stream() {
        let mut encoded = Vec::new();
        handoff()
            .write_from(
                &enrollment(),
                &mut &b"abc"[..],
                3,
                &mut &b"run"[..],
                3,
                &mut &b"cpu"[..],
                3,
                &mut &b"dsk"[..],
                3,
                &mut &b"lif"[..],
                3,
                &mut &b"def"[..],
                3,
                &mut encoded,
            )
            .unwrap();
        let secret_offset = 12
            + (1 + 4 + 1)
            + (1 + 4 + 2)
            + (1 + 4 + 1)
            + (1 + 4 + 2)
            + (1 + 4 + 1)
            + (1 + 4 + 1)
            + 5;
        let mut invalid = encoded.clone();
        invalid[secret_offset] = b'[';
        let mut input = invalid.as_slice();
        let _ = Handoff::read_metadata(&mut input).unwrap();
        assert!(matches!(
            Handoff::read_enrollment(&mut input),
            Err(HandoffError::InvalidEnrollment)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        let mut input = trailing.as_slice();
        let _ = Handoff::read_metadata(&mut input).unwrap();
        let _ = Handoff::read_enrollment(&mut input).unwrap();
        Handoff::read_component_into(&mut input, &mut Vec::new(), 3).unwrap();
        assert_eq!(
            Handoff::read_acquirer_into(&mut input, &mut Vec::new(), 3),
            Err(HandoffError::InvalidSection)
        );
    }
    #[test]
    fn strict_origin_and_token_rules() {
        assert_eq!(
            Enrollment::new("https://hub.example/", "enk_enroll_ok")
                .unwrap()
                .hub_origin(),
            "https://hub.example"
        );
        for origin in [
            "https://hub.example/path",
            "https://:",
            "https://[nope]",
            "https://[::1",
            "https://hub.example:0",
            "https://hub.example:65536",
            "https://-bad.example",
            "https://bad-.example",
            "https://hub..example",
        ] {
            assert!(
                Enrollment::new(origin, "enk_enroll_ok").is_err(),
                "{origin}"
            )
        }
        assert!(Enrollment::new("https://[::1]:3000", "enk_enroll_ok").is_ok());
        assert!(Enrollment::new("https://hub.example", "enk_enroll_ok").is_ok());
        assert!(Enrollment::new("https://hub.example", "not-an-enrollment").is_err());
    }
}
