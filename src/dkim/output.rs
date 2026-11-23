/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM1 verification results: [`DkimResult`] and [`DkimOutput`].

use super::Signature;
use crate::{DnsError, Error, message::MessageIdentity};
use std::fmt::Display;

/// The verification instance a [`DkimOutput`] belongs to.
///
/// A value binds the identity of the parsed message snapshot to the identity
/// of one signature's scope. Every output produced while verifying that
/// signature carries the same message identity, while outputs for another
/// message or another signature carry a different value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DkimVerification {
    pub(crate) message: MessageIdentity,
    pub(crate) signature: [u8; 16],
    pub(crate) signature_len: u64,
    pub(crate) position: u64,
}

impl DkimVerification {
    /// Returns the identity of the message snapshot this result was computed
    /// from.
    pub fn message_identity(&self) -> MessageIdentity {
        self.message
    }

    /// Returns the opaque identity of the signature scope this result was
    /// computed for.
    pub fn signature_identity(&self) -> [u8; 16] {
        self.signature
    }

    /// Returns the length in bytes of the signature header value that was
    /// evaluated.
    pub fn signature_len(&self) -> u64 {
        self.signature_len
    }

    /// Returns the zero-based position of the signature header in the parsed
    /// message.
    pub fn signature_position(&self) -> u64 {
        self.position
    }

    /// Alias for [`signature_position`](Self::signature_position).
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Returns `true` when this result was produced for `message`.
    pub fn is_for_message(&self, message: &crate::AuthenticatedMessage<'_>) -> bool {
        self.message == message.identity()
    }
}

/// Alias for [`DkimVerification`].
pub type DkimEvaluation = DkimVerification;

/// Alias for [`DkimVerification`].
pub type DkimVerificationIdentity = DkimVerification;

/// The outcome of verifying one DKIM1 signature, using the result names of
/// RFC 8601, Section 2.7.1.
///
/// Produced by [`MessageAuthenticator::verify_dkim`](crate::MessageAuthenticator::verify_dkim)
/// inside each [`DkimOutput`]. Every variant other than `Pass` and `None`
/// carries the error that caused it.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DkimResult {
    /// The signature verified.
    Pass,
    /// The signature could not be evaluated: it is malformed, uses an
    /// unsupported version, algorithm or canonicalization, was ignored for
    /// carrying `l=` in strict mode, has expired, or its body hash does not
    /// match the message.
    Neutral(crate::Error),
    /// The signature was evaluated and is invalid: the cryptographic check
    /// failed or the `i=` domain does not match `d=`.
    Fail(crate::Error),
    /// A permanent error while fetching the key: the key record does not
    /// exist, is invalid, has been revoked or uses an unsupported key type.
    PermError(crate::Error),
    /// A transient DNS error while fetching the key; retrying later may
    /// succeed.
    TempError(crate::Error),
    /// No signature was evaluated. `verify_dkim` never returns it (a message
    /// without signatures yields an empty vector); it appears in other
    /// outputs, such as ARC, when there is nothing to verify.
    None,
}

/// The verification result of one DKIM1 signature.
///
/// [`MessageAuthenticator::verify_dkim`](crate::MessageAuthenticator::verify_dkim)
/// returns one output per parsed `DKIM-Signature` header, plus a `neutral`
/// output without a signature for each header rejected with an
/// [`Error::Dkim`] error (such as an unsupported algorithm
/// or version). Headers that fail to parse for other reasons, such as a
/// missing tag or invalid base64, produce no output. Besides the
/// [`DkimResult`], it records the parsed signature (when the header could be
/// parsed), the RFC 6651 failure report address and whether the result comes
/// from an RFC 6541 ATPS check. Use `From<DkimResult>` and
/// [`with_signature`](Self::with_signature) to synthesize an output, for
/// example in tests or when feeding DMARC, which needs the signature's `d=`
/// domain for alignment.
///
/// Outputs produced by
/// [`verify_dkim`](crate::MessageAuthenticator::verify_dkim) also carry the
/// parsed message snapshot and a [`DkimVerification`] binding that snapshot to
/// the signature scope that was evaluated. Use
/// [`verification`](Self::verification) or
/// [`message_identity`](Self::message_identity) to detect results that belong
/// to another message revision.
#[derive(Debug, Clone)]
pub struct DkimOutput<'x> {
    pub(crate) result: DkimResult,
    pub(crate) signature: Option<&'x Signature>,
    pub(crate) report: Option<String>,
    pub(crate) is_atps: bool,
    /// The message snapshot and signature scope this result belongs to.
    /// `None` for outputs synthesized outside the verifier.
    pub(crate) verification: Option<DkimVerification>,
    /// The parsed message snapshot this result was computed from.
    pub(crate) message: Option<&'x crate::AuthenticatedMessage<'x>>,
}

impl PartialEq for DkimOutput<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.result == other.result
            && self.signature == other.signature
            && self.report == other.report
            && self.is_atps == other.is_atps
    }
}

impl Eq for DkimOutput<'_> {}

impl<'x> DkimOutput<'x> {
    pub(crate) fn pass() -> Self {
        DkimOutput {
            result: DkimResult::Pass,
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }

    pub(crate) fn perm_err(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::PermError(err),
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }

    pub(crate) fn temp_err(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::TempError(err),
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }

    pub(crate) fn fail(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::Fail(err),
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }

    pub(crate) fn neutral(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::Neutral(err),
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }

    pub(crate) fn dns_error(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            DkimOutput::temp_err(err)
        } else {
            DkimOutput::perm_err(err)
        }
    }

    /// Attaches the signature this result refers to.
    ///
    /// Used to build an output outside the verifier, for example from a
    /// cached result, so that DMARC can check its `d=` domain for alignment.
    pub fn with_signature(mut self, signature: &'x Signature) -> Self {
        self.signature = signature.into();
        self
    }

    pub(crate) fn with_atps(mut self) -> Self {
        self.is_atps = true;
        self
    }

    pub(crate) fn with_verification(mut self, verification: DkimVerification) -> Self {
        self.verification = Some(verification);
        self
    }

    pub(crate) fn with_message_snapshot(
        mut self,
        message: &'x crate::AuthenticatedMessage<'x>,
    ) -> Self {
        self.message = Some(message);
        self
    }

    /// Returns the verification instance this result belongs to.
    ///
    /// `None` when the output was built outside a verifier, for example with
    /// [`From<DkimResult>`](DkimOutput::from). Use
    /// [`is_for_message`](Self::is_for_message) to check an output against a
    /// particular message snapshot.
    pub fn verification(&self) -> Option<&DkimVerification> {
        self.verification.as_ref()
    }

    /// Returns the parsed message snapshot this result was computed from.
    ///
    /// `None` for outputs synthesized outside the verifier.
    pub fn message(&self) -> Option<&'x crate::AuthenticatedMessage<'x>> {
        self.message
    }

    /// Alias for [`message`](Self::message).
    pub fn message_snapshot(&self) -> Option<&'x crate::AuthenticatedMessage<'x>> {
        self.message
    }

    /// Alias for [`verification`](Self::verification).
    pub fn evaluation(&self) -> Option<&DkimVerification> {
        self.verification()
    }

    /// Returns the verification instance by value.
    pub fn verification_identity(&self) -> Option<DkimVerification> {
        self.verification
    }

    /// Alias for [`verification_identity`](Self::verification_identity).
    pub fn evaluation_identity(&self) -> Option<DkimVerification> {
        self.verification
    }

    /// Returns the opaque identity of the signature scope this result was
    /// computed for.
    pub fn signature_identity(&self) -> Option<[u8; 16]> {
        self.verification
            .map(|verification| verification.signature)
    }

    /// Alias for [`signature_identity`](Self::signature_identity).
    pub fn signature_scope(&self) -> Option<[u8; 16]> {
        self.signature_identity()
    }

    /// Returns the identity of the message snapshot this result was computed
    /// from.
    pub fn message_identity(&self) -> Option<MessageIdentity> {
        self.verification.map(|verification| verification.message)
    }

    /// Returns `true` when this result was produced for `message`.
    ///
    /// An output without a recorded verification instance returns `true`, so
    /// synthetic outputs remain usable with the historical API.
    pub fn is_for_message(&self, message: &crate::AuthenticatedMessage<'_>) -> bool {
        if let Some(snapshot) = self.message {
            return snapshot.identity() == message.identity();
        }
        self.verification
            .is_none_or(|verification| verification.is_for_message(message))
    }

    /// Returns `true` when this result belongs to `verification`.
    ///
    /// An output without a recorded verification instance returns `false`.
    pub fn is_for_verification(&self, verification: &DkimVerification) -> bool {
        self.verification
            .is_some_and(|recorded| recorded == *verification)
    }

    /// Returns the verification result.
    pub fn result(&self) -> &DkimResult {
        &self.result
    }

    /// Returns the parsed signature this result refers to, or `None` when the
    /// `DKIM-Signature` header could not be parsed.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature
    }

    /// Returns the address to send an RFC 6651 failure report to.
    ///
    /// Set only when the signature has `r=y`, did not pass, the signer's
    /// `_report._domainkey.<d>` record exists, the `rp=` sampling percentage
    /// selected this failure and the `rr=` tag requests reports for this kind
    /// of failure. The address is `<ra>@<d>`.
    pub fn report_address(&self) -> Option<&str> {
        self.report.as_deref()
    }

    /// Returns `true` when the result comes from an RFC 6541 ATPS check: the
    /// signature verified, its `atps=` domain matched the `From` domain and
    /// the ATPS record lookup determined the result.
    pub fn is_atps(&self) -> bool {
        self.is_atps
    }
}

impl From<DkimResult> for DkimOutput<'_> {
    fn from(result: DkimResult) -> Self {
        DkimOutput {
            result,
            signature: None,
            report: None,
            is_atps: false,
            verification: None,
            message: None,
        }
    }
}

impl From<Error> for DkimResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            DkimResult::TempError(err)
        } else {
            DkimResult::PermError(err)
        }
    }
}

impl Display for DkimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimResult::Pass => f.write_str("pass"),
            DkimResult::Fail(err) => write!(f, "fail; {err}"),
            DkimResult::Neutral(err) => write!(f, "neutral; {err}"),
            DkimResult::TempError(err) => write!(f, "temp error; {err}"),
            DkimResult::PermError(err) => write!(f, "perm error; {err}"),
            DkimResult::None => f.write_str("none"),
        }
    }
}
