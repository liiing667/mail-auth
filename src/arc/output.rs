/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainLink, ChainValidation};
use crate::{DkimResult, MessageIdentity};

/// The result of ARC chain validation (RFC 8617, Section 5.2).
///
/// An alias of [`DkimResult`]: `Pass` when the chain validated, `None` when
/// the message has no ARC headers, and `Fail`, `Neutral`, `PermError` or
/// `TempError` carrying the error that stopped validation. See
/// [`MessageAuthenticator::verify_arc`](crate::MessageAuthenticator::verify_arc)
/// for when each variant is returned.
pub type ArcResult = DkimResult;

/// The outcome of ARC chain validation.
///
/// Returned by
/// [`MessageAuthenticator::verify_arc`](crate::MessageAuthenticator::verify_arc)
/// and passed to [`ArcSealer::seal`](super::ArcSealer::seal) and to
/// [`AuthenticationResults::with_arc_result`](crate::AuthenticationResults::with_arc_result).
/// Built from a bare [`ArcResult`] through `From`, with an empty chain.
#[derive(Debug, Clone)]
pub struct ArcOutput<'x> {
    pub(crate) result: ArcResult,
    pub(crate) set: Vec<ChainLink<'x>>,
    /// Identity of the message revision this validation describes. `None`
    /// for a synthetic or default output.
    pub(crate) message: Option<MessageIdentity>,
}

impl PartialEq for ArcOutput<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.result == other.result && self.set == other.set
    }
}

impl Eq for ArcOutput<'_> {}

impl ArcOutput<'_> {
    /// Returns the chain validation result.
    pub fn result(&self) -> &ArcResult {
        &self.result
    }

    /// Returns the ARC sets of the incoming chain, oldest (instance 1)
    /// first. Empty when the message has no ARC headers or they could not be
    /// grouped into sets.
    pub fn chain(&self) -> &[ChainLink<'_>] {
        &self.set
    }
}

impl<'x> ArcOutput<'x> {
    pub(crate) fn with_result(mut self, result: ArcResult) -> Self {
        self.result = result;
        self
    }

    /// Returns the identity of the message revision this validation belongs
    /// to, or `None` for a synthetic output.
    pub fn message_identity(&self) -> Option<MessageIdentity> {
        self.message
    }

    /// Returns `true` when this validation was produced for `message`.
    ///
    /// An output without recorded identity returns `true`, so synthetic
    /// outputs remain usable with the historical API.
    pub fn is_for_message(&self, message: &crate::AuthenticatedMessage<'_>) -> bool {
        self.message
            .is_none_or(|identity| identity == message.identity())
    }

    /// Returns `true` when a new ARC set may be added: the chain is empty or
    /// its newest `ARC-Seal` does not carry `cv=fail` (RFC 8617,
    /// Section 5.1.2).
    pub fn can_be_sealed(&self) -> bool {
        self.set.is_empty() || self.set.last().unwrap().seal.header.cv != ChainValidation::Fail
    }
}

impl From<ArcResult> for ArcOutput<'_> {
    fn from(result: ArcResult) -> Self {
        ArcOutput {
            result,
            set: Vec::new(),
            message: None,
        }
    }
}

impl Default for ArcOutput<'_> {
    fn default() -> Self {
        Self {
            result: DkimResult::None,
            set: Vec::new(),
            message: None,
        }
    }
}
