/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{RR_FAIL, RR_NEUTRAL_NONE, RR_SOFTFAIL, RR_TEMP_PERM_ERROR, SpfRecord};
use crate::Error;
use crate::sampling::is_within_pct;
use std::{fmt::Display, str::FromStr};

/// The result of an SPF check (RFC 7208, Section 2.6).
///
/// Displays as the lowercase RFC token (`pass`, `fail`, `softfail`,
/// `neutral`, `temperror`, `permerror`, `none`) and parses from the same
/// tokens, ignoring case, through [`FromStr`] (which fails with
/// [`Error::Parse`] on any other input).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SpfResult {
    /// The client is authorized to use the domain (Section 2.6.3).
    Pass,
    /// The client is explicitly not authorized to use the domain
    /// (Section 2.6.4).
    Fail,
    /// The client is probably not authorized, a weak statement between
    /// `fail` and `neutral` (Section 2.6.5).
    SoftFail,
    /// The domain owner makes no assertion about the client (Section 2.6.2).
    /// Also returned when no directive matches.
    Neutral,
    /// A transient error, usually a DNS failure, prevented the check
    /// (Section 2.6.6).
    TempError,
    /// The published record could not be interpreted, or a processing limit
    /// was exceeded (Section 2.6.7).
    PermError,
    /// No SPF record was found, or the domain is not a valid, fully qualified
    /// name (Section 2.6.1).
    None,
}

/// Snapshot of the state that was fixed for one SPF evaluation.
///
/// A `check_host()` call has one report. [`verify_spf`](crate::MessageAuthenticator::verify_spf)
/// checks HELO and MAIL FROM as separate evaluations under RFC 7208 and
/// returns the report of the identity whose output is returned.
///
/// The report is attached to [`SpfOutput`] and stays readable after the
/// evaluation has finished. It is not part of [`SpfOutput`] equality, so
/// synthetic outputs built with [`SpfOutput::new`] compare as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfEvaluationReport {
    /// The unique generation of this evaluation.
    pub generation: u64,
    /// How many checks ran in this evaluation.
    pub attempts: u32,
    /// The number of DNS-querying mechanisms permitted by the evaluation.
    pub query_limit: u32,
    /// How many DNS-querying mechanisms the evaluation has consumed.
    pub queries_used: u32,
    /// The opaque generation of the DNS cache used by the evaluation.
    pub cache_generation: u64,
    /// The domain of the SPF record that produced the final result.
    pub source: Option<String>,
    /// The last DNS key looked up by the evaluation.
    pub dns_key: Option<String>,
    /// The qualifier that ended the evaluation.
    pub qualifier: SpfResult,
}

impl Default for SpfEvaluationReport {
    fn default() -> Self {
        SpfEvaluationReport {
            generation: 0,
            attempts: 0,
            query_limit: 10,
            queries_used: 0,
            cache_generation: 0,
            source: None,
            dns_key: None,
            qualifier: SpfResult::None,
        }
    }
}

impl SpfEvaluationReport {
    /// Returns the unique generation of this evaluation.
    ///
    /// Retries of the same check reuse the generation and its budget.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Alias for [`SpfEvaluationReport::generation`].
    pub fn transaction_generation(&self) -> u64 {
        self.generation
    }

    /// Returns how many checks were run in this evaluation. Retrying the same
    /// identity increments the count; a different identity starts a new
    /// evaluation and resets it.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the number of DNS-querying mechanisms permitted by the
    /// evaluation (ten).
    pub fn query_limit(&self) -> u32 {
        self.query_limit
    }

    /// Returns how many DNS-querying mechanisms this evaluation has consumed.
    /// The initial TXT lookup of the domain is not counted, matching RFC
    /// 7208 Section 4.6.4.
    pub fn queries_used(&self) -> u32 {
        self.queries_used
    }

    /// Returns the number of querying mechanisms still available. Retries of
    /// the same evaluation never increase this value.
    pub fn queries_remaining(&self) -> u32 {
        self.query_limit.saturating_sub(self.queries_used)
    }

    /// Returns the opaque generation of the DNS cache used by the
    /// evaluation. It is `0` when the check ran without a cache.
    pub fn cache_generation(&self) -> u64 {
        self.cache_generation
    }

    /// Returns the domain of the SPF record that was being evaluated when
    /// the final qualifier was decided (or when the check failed).
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Alias for [`SpfEvaluationReport::source`], matching the macro source
    /// terminology used by the evaluator.
    pub fn macro_source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Alias for [`SpfEvaluationReport::source`].
    pub fn record_source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Returns the last DNS key looked up by this evaluation.
    ///
    /// The key is the name produced by macro expansion for the last TXT, MX,
    /// A or AAAA lookup, or the client address for a PTR lookup. Returns
    /// `None` before any lookup has run.
    pub fn dns_key(&self) -> Option<&str> {
        self.dns_key.as_deref()
    }

    /// Returns the qualifier that ended the evaluation.
    pub fn qualifier(&self) -> SpfResult {
        self.qualifier
    }

    /// Alias for [`SpfEvaluationReport::qualifier`].
    pub fn result(&self) -> SpfResult {
        self.qualifier
    }
}

/// Alias for [`SpfEvaluationReport`].
pub type SpfReport = SpfEvaluationReport;

/// Alias for [`SpfEvaluationReport`].
pub type SpfTransactionReport = SpfEvaluationReport;

/// The outcome of an SPF check.
///
/// Returned by [`MessageAuthenticator::verify_spf`] and
/// [`MessageAuthenticator::check_host`]. Besides the [`SpfResult`], it
/// carries the checked domain, the explanation string of a `fail` result and
/// the RFC 6652 report address, when the record requests a report for this
/// result. [`SpfOutput::new`] and [`SpfOutput::with_result`] build a
/// synthetic output, for example to feed DMARC with a result obtained
/// elsewhere.
///
/// [`MessageAuthenticator::verify_spf`]: crate::MessageAuthenticator::verify_spf
/// [`MessageAuthenticator::check_host`]: crate::MessageAuthenticator::check_host
#[derive(Debug, Eq, Clone)]
pub struct SpfOutput {
    pub(crate) result: SpfResult,
    pub(crate) domain: String,
    pub(crate) report: Option<String>,
    pub(crate) explanation: Option<String>,
    pub(crate) identity: Option<SpfIdentity>,
    pub(crate) evaluation: Option<SpfEvaluationReport>,
}

impl PartialEq for SpfOutput {
    fn eq(&self, other: &Self) -> bool {
        self.result == other.result
            && self.domain == other.domain
            && self.report == other.report
            && self.explanation == other.explanation
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum SpfIdentity {
    Helo,
    MailFrom,
}

impl FromStr for SpfResult {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        hashify::map_ignore_case!(value.as_bytes(), SpfResult,
            b"pass" => SpfResult::Pass,
            b"fail" => SpfResult::Fail,
            b"softfail" => SpfResult::SoftFail,
            b"neutral" => SpfResult::Neutral,
            b"temperror" => SpfResult::TempError,
            b"permerror" => SpfResult::PermError,
            b"none" => SpfResult::None,
        )
        .copied()
        .ok_or(Error::Parse)
    }
}

impl SpfOutput {
    /// Creates an output for `domain` with result [`SpfResult::None`], no
    /// explanation and no report address.
    pub fn new(domain: String) -> Self {
        SpfOutput {
            result: SpfResult::None,
            report: None,
            explanation: None,
            domain,
            identity: None,
            evaluation: None,
        }
    }

    pub(crate) fn with_identity(mut self, identity: SpfIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets the result.
    pub fn with_result(mut self, result: SpfResult) -> Self {
        self.result = result;
        self
    }

    /// Sets the report address to `<ra>@<domain>` when `spf` has an `ra=`
    /// modifier, its `rr=` bitmask covers the current result and the message
    /// is sampled by `rp=` (RFC 6652, Section 3). Call it after
    /// [`SpfOutput::with_result`]; a `pass` result never produces a report.
    pub fn with_report(mut self, spf: &SpfRecord) -> Self {
        match &spf.ra {
            Some(ra)
                if is_within_pct(spf.rp)
                    && match self.result {
                        SpfResult::Fail => (spf.rr & RR_FAIL) != 0,
                        SpfResult::SoftFail => (spf.rr & RR_SOFTFAIL) != 0,
                        SpfResult::Neutral | SpfResult::None => (spf.rr & RR_NEUTRAL_NONE) != 0,
                        SpfResult::TempError | SpfResult::PermError => {
                            (spf.rr & RR_TEMP_PERM_ERROR) != 0
                        }
                        SpfResult::Pass => false,
                    } =>
            {
                let ra = String::from_utf8_lossy(ra);
                let mut report = String::with_capacity(ra.len() + self.domain.len() + 1);
                report.push_str(ra.as_ref());
                report.push('@');
                report.push_str(&self.domain);
                self.report = report.into();
            }
            _ => (),
        }
        self
    }

    pub(crate) fn with_evaluation(mut self, evaluation: SpfEvaluationReport) -> Self {
        self.evaluation = Some(evaluation);
        self
    }

    /// Sets the explanation string (RFC 7208, Section 6.2).
    pub fn with_explanation(mut self, explanation: String) -> Self {
        self.explanation = explanation.into();
        self
    }

    /// Returns the SPF result.
    pub fn result(&self) -> SpfResult {
        self.result
    }

    /// Returns the domain that was checked: the HELO domain or the domain of
    /// the MAIL FROM address.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the expanded `exp=` explanation, set only on a `fail` result
    /// whose record has an `exp=` modifier that resolved.
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Returns the address that requested an authentication failure report
    /// for this result (RFC 6652), if any.
    pub fn report_address(&self) -> Option<&str> {
        self.report.as_deref()
    }

    /// Returns the state fixed for this SPF evaluation: its generation,
    /// source record, cache generation, query budget and final qualifier.
    ///
    /// Returns `None` for an output built with [`SpfOutput::new`] rather than
    /// returned by a verifier.
    pub fn evaluation(&self) -> Option<&SpfEvaluationReport> {
        self.evaluation.as_ref()
    }

    /// Alias for [`SpfOutput::evaluation`].
    pub fn evaluation_report(&self) -> Option<&SpfEvaluationReport> {
        self.evaluation.as_ref()
    }

    /// Alias for [`SpfOutput::evaluation`] returning an owned snapshot.
    pub fn transaction(&self) -> Option<SpfEvaluationReport> {
        self.evaluation.clone()
    }

    /// Returns the generation of the evaluation attached to this output, or
    /// `0` for a synthetic output.
    pub fn transaction_generation(&self) -> u64 {
        self.evaluation
            .as_ref()
            .map_or(0, |evaluation| evaluation.generation())
    }

    /// Returns the number of attempts of the evaluation attached to this
    /// output, or `0` for a synthetic output.
    pub fn attempts(&self) -> u32 {
        self.evaluation
            .as_ref()
            .map_or(0, |evaluation| evaluation.attempts())
    }

    /// Returns the cache generation of the evaluation attached to this
    /// output, or `0` for a synthetic output.
    pub fn cache_generation(&self) -> u64 {
        self.evaluation
            .as_ref()
            .map_or(0, |evaluation| evaluation.cache_generation())
    }

    /// Returns the source record domain of the evaluation attached to this
    /// output, or `None` for a synthetic output.
    pub fn source(&self) -> Option<&str> {
        self.evaluation
            .as_ref()
            .and_then(|evaluation| evaluation.source())
    }

    /// Alias for [`SpfOutput::source`].
    pub fn macro_source(&self) -> Option<&str> {
        self.source()
    }
}

impl Default for SpfOutput {
    fn default() -> Self {
        Self {
            result: SpfResult::None,
            domain: Default::default(),
            report: Default::default(),
            explanation: Default::default(),
            identity: None,
            evaluation: None,
        }
    }
}

impl Display for SpfResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
            SpfResult::None => "none",
        })
    }
}
