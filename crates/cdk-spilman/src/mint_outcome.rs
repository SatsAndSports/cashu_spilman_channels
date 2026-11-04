//! Evidence returned by mint networking, separate from human-readable diagnostics.
//!
//! A response is not proof of successful settlement: callers must still verify
//! signatures and outputs. In particular, an HTTP failure is not proof that
//! funding inputs remain spendable.

use serde::{Deserialize, Serialize};

/// A complete HTTP response from a mint. Adapters must not construct this from
/// a truncated, oversized, or undecodable body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintResponse {
    /// HTTP status observed by the networking adapter.
    pub status: u16,
    /// Complete UTF-8 response body, before application JSON parsing.
    pub body: String,
}

/// A validated NUT-00 rejection observed in an HTTP 400 response.
///
/// This is evidence of rejection of this request, not evidence that the input
/// proofs are unspent (for example, code 11001 reports already-spent proofs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RejectionFields")]
pub struct MintRejection {
    status: u16,
    code: u32,
    detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionFields {
    status: u16,
    code: u32,
    detail: String,
}

impl TryFrom<RejectionFields> for MintRejection {
    type Error = &'static str;
    fn try_from(fields: RejectionFields) -> Result<Self, Self::Error> {
        if fields.status != 400 {
            return Err("NUT-00 rejection must have HTTP status 400");
        }
        Ok(Self {
            status: fields.status,
            code: fields.code,
            detail: fields.detail,
        })
    }
}

impl MintRejection {
    /// HTTP status associated with this rejection.
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Checked NUT-00 code, without integer narrowing.
    pub fn code(&self) -> u32 {
        self.code
    }
    /// Untrusted human-readable mint detail, never used for retry decisions.
    pub fn detail(&self) -> &str {
        &self.detail
    }
    /// Whether this rejection permits attempting selection of a new keyset.
    /// Unknown codes and the ambiguous historical 99999 workaround do not.
    pub fn permits_keyset_retry(&self) -> bool {
        self.status == 400 && matches!(self.code, 12001 | 12002)
    }
}

/// Failure evidence from a mint request. Transport diagnostics are never parsed
/// as mint errors, even when they happen to contain JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MintRequestError {
    /// Complete, well-formed NUT-00 rejection at the specified status.
    Rejected {
        /// Validated response evidence.
        rejection: MintRejection,
    },
    /// Complete HTTP response that does not establish a protocol rejection.
    Http {
        /// Complete response whose status/body did not establish a rejection.
        response: MintResponse,
    },
    /// Request/response failure with an unknown submission outcome.
    Transport {
        /// Diagnostic only; never interpreted as protocol evidence.
        message: String,
    },
}

impl MintRequestError {
    /// Record a networking failure without interpreting its diagnostic text.
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
        }
    }
    /// Rejection evidence, if the response was validated as NUT-00.
    pub fn rejection(&self) -> Option<&MintRejection> {
        match self {
            Self::Rejected { rejection } => Some(rejection),
            _ => None,
        }
    }
    /// Permission to reselect after this request, not an automatic replay rule.
    pub fn permits_keyset_retry(&self) -> bool {
        self.rejection()
            .is_some_and(|rejection| rejection.status == 400 && rejection.permits_keyset_retry())
    }
}

impl MintResponse {
    /// Decode the binding contract: a successful callback returns a
    /// serialized `{status, body}` response, not a bare mint body. Exceptions
    /// and rejected promises are transport failures regardless of their text.
    pub fn from_callback(result: Result<String, String>) -> Result<String, MintRequestError> {
        let wire = result.map_err(MintRequestError::transport)?;
        let response: Self = serde_json::from_str(&wire)
            .map_err(|_| MintRequestError::transport("invalid mint response envelope"))?;
        if !(100..600).contains(&response.status) {
            return Err(MintRequestError::transport("invalid mint HTTP status"));
        }
        response.into_result()
    }
    /// Classify a complete response. Only HTTP 400 with a validated NUT-00 body
    /// establishes a rejection; 5xx bodies cannot authorize changed requests.
    pub fn into_result(self) -> Result<String, MintRequestError> {
        if (200..300).contains(&self.status) {
            return Ok(self.body);
        }
        if self.status == 400 {
            // Derived struct parsing rejects duplicate known fields and numeric
            // overflow. Unknown extension fields remain permitted by NUT-00.
            #[derive(Deserialize)]
            struct Nut00 {
                code: u32,
                detail: String,
            }
            if let Ok(error) = serde_json::from_str::<Nut00>(&self.body) {
                return Err(MintRequestError::Rejected {
                    rejection: MintRejection {
                        status: self.status,
                        code: error.code,
                        detail: error.detail,
                    },
                });
            }
        }
        Err(MintRequestError::Http { response: self })
    }
}

impl std::fmt::Display for MintRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { rejection } => write!(
                f,
                "mint rejected request (HTTP {}, NUT-00 {})",
                rejection.status, rejection.code
            ),
            Self::Http { response } => {
                write!(f, "unclassified mint HTTP response {}", response.status)
            }
            Self::Transport { message } => write!(f, "mint transport failure: {message}"),
        }
    }
}
impl std::error::Error for MintRequestError {}

impl From<String> for MintRequestError {
    fn from(message: String) -> Self {
        Self::transport(message)
    }
}
impl From<&str> for MintRequestError {
    fn from(message: &str) -> Self {
        Self::transport(message)
    }
}

impl From<MintRequestError> for String {
    fn from(error: MintRequestError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_envelopes_cannot_promote_exception_text_or_bare_bodies() {
        let body = r#"{"code":12002,"detail":"inactive"}"#;
        let wire = serde_json::to_string(&MintResponse {
            status: 400,
            body: body.to_owned(),
        })
        .unwrap();
        assert!(MintResponse::from_callback(Ok(wire.clone()))
            .unwrap_err()
            .permits_keyset_retry());
        for result in [
            Err(wire),
            Err(body.to_owned()),
            Ok(body.to_owned()),
            Ok(r#"{"status":400,"status":200,"body":"{}"}"#.to_owned()),
        ] {
            assert!(matches!(
                MintResponse::from_callback(result),
                Err(MintRequestError::Transport { .. })
            ));
        }
        assert!(serde_json::from_str::<MintRejection>(
            r#"{"status":503,"code":12002,"detail":"no"}"#
        )
        .is_err());
    }

    #[test]
    fn rejection_requires_complete_protocol_evidence() {
        let valid = r#"{"code":12002,"detail":"inactive keyset"}"#;
        for status in [0, 200, 302, 401, 429, 500, 503, 65535] {
            let result = MintResponse {
                status,
                body: valid.to_owned(),
            }
            .into_result();
            assert!(!result.err().is_some_and(|e| e.permits_keyset_retry()));
        }
        for body in [
            r#"{"code":4294979298,"detail":"overflow"}"#,
            r#"{"code":12002,"code":11001,"detail":"duplicate"}"#,
            r#"{"code":12002,"detail":"a","detail":"b"}"#,
            r#"{"code":12002}"#,
            r#"{"code":12002,"detail":null}"#,
            r#"{"code":12002.0,"detail":"float"}"#,
            r#"{"code":-1,"detail":"negative"}"#,
            r#"{"code":12002,"detail":"truncated""#,
        ] {
            assert!(matches!(
                MintResponse {
                    status: 400,
                    body: body.to_owned()
                }
                .into_result(),
                Err(MintRequestError::Http { .. })
            ));
        }
        let error = MintResponse {
            status: 400,
            body: valid.to_owned(),
        }
        .into_result()
        .unwrap_err();
        assert!(error.permits_keyset_retry());
        assert!(!MintRequestError::transport(valid).permits_keyset_retry());
    }

    #[test]
    fn spent_and_unknown_rejections_do_not_authorize_keyset_retry() {
        for code in [11001, 12000, 12999, 99999, u32::MAX] {
            let error = MintResponse {
                status: 400,
                body: format!(r#"{{"code":{code},"detail":"rejected"}}"#),
            }
            .into_result()
            .unwrap_err();
            assert!(error.rejection().is_some());
            assert!(!error.permits_keyset_retry());
        }
    }
}
