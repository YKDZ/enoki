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
        ureq::Error::Status(status, response) => HttpAttemptError::HttpStatus {
            message: response.status_text().to_string(),
            status,
        },
        ureq::Error::Transport(error) => HttpAttemptError::Network(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

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
