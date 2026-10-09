use std::{error::Error, fmt, io::Read};

/// One HTTP attempt that did not obtain a protobuf response.
///
/// Classification lives here so Registration and every authenticated Probe
/// report agree on which failures may be retried.
#[derive(Debug)]
pub enum HttpAttemptError {
    Network(String),
    ResponseRead(std::io::Error),
    HttpStatus { message: String, status: u16 },
}

impl HttpAttemptError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network(_) | Self::ResponseRead(_) => true,
            Self::HttpStatus { status, .. } => {
                *status == 408 || *status == 429 || (500..=599).contains(status)
            }
        }
    }
}

impl fmt::Display for HttpAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(message) => write!(formatter, "network request failed: {message}"),
            Self::ResponseRead(error) => write!(formatter, "response read failed: {error}"),
            Self::HttpStatus { message, status } => {
                write!(formatter, "HTTP {status}: {message}")
            }
        }
    }
}

impl Error for HttpAttemptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResponseRead(error) => Some(error),
            Self::Network(_) | Self::HttpStatus { .. } => None,
        }
    }
}

/// Sends one protobuf request. Callers may add authentication headers; this
/// module owns the shared response and HTTP-failure boundary.
pub fn post_protobuf(
    url: &str,
    body: &[u8],
    headers: &[(&str, String)],
) -> Result<Vec<u8>, HttpAttemptError> {
    let mut request = ureq::post(url)
        .set("accept", "application/x-protobuf")
        .set("content-type", "application/x-protobuf");
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = request.send_bytes(body).map_err(http_attempt_error)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(HttpAttemptError::ResponseRead)?;
    Ok(bytes)
}

fn http_attempt_error(error: ureq::Error) -> HttpAttemptError {
    match error {
        ureq::Error::Status(status, response) => {
            let status_text = response.status_text().to_string();
            let message = match hub_error_code(response) {
                Some(code) => format!("{status_text} ({code})"),
                None => status_text,
            };
            HttpAttemptError::HttpStatus { message, status }
        }
        ureq::Error::Transport(error) => HttpAttemptError::Network(error.to_string()),
    }
}

/// Hub error bodies are `{ "error": <code> }`; keeping that code is the whole
/// point of this narrow read, so anything unreadable or non-string keeps the
/// plain status text and the original classification.
fn hub_error_code(response: ureq::Response) -> Option<String> {
    const MAX_ERROR_BODY_BYTES: u64 = 4096;
    let mut body = Vec::new();
    if response
        .into_reader()
        .take(MAX_ERROR_BODY_BYTES)
        .read_to_end(&mut body)
        .is_err()
    {
        return None;
    }
    match serde_json::from_slice::<serde_json::Value>(&body)
        .ok()?
        .get("error")?
    {
        serde_json::Value::String(code) => Some(code.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(2);

    /// Serves one raw HTTP response to a single request on a private loopback port.
    fn serve(status_line: &str, content_type: &str, body: &[u8]) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("loopback address").port();
        let mut response = format!(
            "HTTP/1.1 {status_line}\r\ncontent-type: {content_type}\r\nx-hub-detail: header-secret\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(LOOPBACK_TIMEOUT));
            drain_request(&mut stream);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            drain_connection(&mut stream);
        });
        (port, server)
    }

    fn drain_request(stream: &mut TcpStream) {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => head.push(byte[0]),
            }
        }
        let mut remaining = declared_body_len(&head);
        let mut chunk = [0u8; 512];
        while remaining > 0 {
            let limit = remaining.min(chunk.len());
            match stream.read(&mut chunk[..limit]) {
                Ok(0) | Err(_) => break,
                Ok(read) => remaining -= read,
            }
        }
    }

    fn declared_body_len(head: &[u8]) -> usize {
        String::from_utf8_lossy(head)
            .to_ascii_lowercase()
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("content-length:"))
            .filter_map(|value| value.trim().parse::<usize>().ok())
            .next()
            .unwrap_or(0)
    }

    fn drain_connection(stream: &mut TcpStream) {
        let mut sink = [0u8; 256];
        loop {
            match stream.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    fn report_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}/api/probe/report")
    }

    #[test]
    fn carries_hub_business_error_code_into_report_rejection_message() {
        let (port, server) = serve(
            "400 Bad Request",
            "application/json",
            br#"{"error":"probe_report_sequence_regression","detail":"body-secret"}"#,
        );
        let error = post_protobuf(
            &report_url(port),
            b"request-secret",
            &[("authorization", "credential-secret".to_string())],
        )
        .expect_err("HTTP 400 must not succeed");
        server.join().expect("loopback server");

        let HttpAttemptError::HttpStatus { message, status } = &error else {
            panic!("HTTP 400 must stay an HttpStatus error: {error}");
        };
        assert_eq!(*status, 400);
        assert_eq!(message, "Bad Request (probe_report_sequence_regression)");
        assert!(
            !error.is_transient(),
            "report rejection must stay permanent"
        );
        let text = error.to_string();
        for secret in [
            "body-secret",
            "credential-secret",
            "request-secret",
            "header-secret",
        ] {
            assert!(!text.contains(secret), "{secret} leaked into {text}");
        }
    }

    #[test]
    fn carries_the_business_error_code_through_the_existing_report_failure_text_and_exit() {
        use crate::runtime::ReportError;
        use crate::runtime::{PERMANENT_REPORT_EXIT_STATUS, ProbeRunError, probe_run_exit_status};

        let (port, server) = serve(
            "400 Bad Request",
            "application/json",
            br#"{"error":"probe_report_window_too_large"}"#,
        );
        let error =
            post_protobuf(&report_url(port), b"body", &[]).expect_err("HTTP 400 must not succeed");
        server.join().expect("loopback server");

        let failure = ProbeRunError::Report(ReportError::Attempt(error));
        assert_eq!(
            failure.to_string(),
            "report request failed: HTTP 400: Bad Request (probe_report_window_too_large)"
        );
        assert_eq!(
            probe_run_exit_status(&failure),
            PERMANENT_REPORT_EXIT_STATUS
        );
    }

    #[test]
    fn keeps_transient_classification_of_the_status_alongside_the_business_error_code() {
        let (port, server) = serve(
            "503 Service Unavailable",
            "application/json",
            br#"{"error":"hub_draining"}"#,
        );
        let error =
            post_protobuf(&report_url(port), b"body", &[]).expect_err("HTTP 503 must not succeed");
        server.join().expect("loopback server");

        assert!(error.is_transient(), "transient status must stay retryable");
        assert_eq!(
            error.to_string(),
            "HTTP 503: Service Unavailable (hub_draining)"
        );
    }

    #[test]
    fn falls_back_to_status_text_when_the_response_has_no_usable_error_code() {
        for body in [
            "<html>proxy error</html>".as_bytes(),
            br#"{"detail":"no error field"}"#,
            br#"{"error":400}"#,
            br#"{"error":"truncated"#,
            b"".as_slice(),
        ] {
            let (port, server) = serve("400 Bad Request", "application/json", body);
            let error = post_protobuf(&report_url(port), b"body", &[])
                .expect_err("HTTP 400 must not succeed");
            server.join().expect("loopback server");

            assert!(
                matches!(error, HttpAttemptError::HttpStatus { status: 400, .. }),
                "unusable body must stay an HttpStatus error: {error}"
            );
            assert_eq!(error.to_string(), "HTTP 400: Bad Request");
            assert!(!error.is_transient(), "400 must stay permanent");
        }
    }

    #[test]
    fn returns_the_response_bytes_of_a_real_successful_report() {
        let payload = [0x08u8, 0x01, 0x12, 0x00, 0xff];
        let (port, server) = serve("200 OK", "application/x-protobuf", &payload);
        let response =
            post_protobuf(&report_url(port), b"body", &[]).expect("HTTP 200 must succeed");
        server.join().expect("loopback server");

        assert_eq!(response, payload);
    }

    #[test]
    fn classifies_only_network_response_read_timeout_rate_limit_and_server_errors_as_transient() {
        let transient = [
            HttpAttemptError::Network("connection reset".to_string()),
            HttpAttemptError::ResponseRead(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "response interrupted",
            )),
            HttpAttemptError::HttpStatus {
                status: 408,
                message: "Request Timeout".to_string(),
            },
            HttpAttemptError::HttpStatus {
                status: 429,
                message: "Too Many Requests".to_string(),
            },
            HttpAttemptError::HttpStatus {
                status: 503,
                message: "Service Unavailable".to_string(),
            },
        ];
        let permanent = [
            HttpAttemptError::HttpStatus {
                status: 400,
                message: "Bad Request".to_string(),
            },
            HttpAttemptError::HttpStatus {
                status: 401,
                message: "Unauthorized".to_string(),
            },
            HttpAttemptError::HttpStatus {
                status: 403,
                message: "Forbidden".to_string(),
            },
            HttpAttemptError::HttpStatus {
                status: 404,
                message: "Not Found".to_string(),
            },
        ];

        assert!(transient.iter().all(HttpAttemptError::is_transient));
        assert!(permanent.iter().all(|error| !error.is_transient()));
    }
}
