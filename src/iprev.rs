/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Reverse IP address verification (`iprev`, RFC 8601 Section 3).
//!
//! The `iprev` check confirms that the SMTP client's IP address has a PTR
//! record whose name resolves back to the same address. Run it with
//! [`MessageAuthenticator::verify_iprev`] and report the outcome with
//! [`AuthenticationResults::with_iprev_result`](crate::AuthenticationResults::with_iprev_result).
//!
//! An `iprev` check is an identity transaction: the client address, the PTR
//! set returned for it, the A/AAAA answers for those names, the cache
//! generation and the final result belong together. The output returned by a
//! verifier records that identity, and
//! [`AuthenticationResults::set_iprev_result`](crate::AuthenticationResults::set_iprev_result)
//! refuses to relabel the result of one client address as the result of a
//! different address.

use crate::dns::{DnsCache, Negative, NoCache, Parameters, RecordSet, ResolverCache};
use crate::{DnsError, Error, Instant, MessageAuthenticator};
use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::Display,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

/// The outcome of an `iprev` check (RFC 8601 Section 3), produced by
/// [`MessageAuthenticator::verify_iprev`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IprevOutput {
    /// The `iprev` result.
    pub result: IprevResult,
    /// The host names returned by the PTR lookup, lowercased. `None` when the
    /// PTR lookup itself failed.
    pub ptr: Option<Arc<[Box<str>]>>,
}

impl Default for IprevOutput {
    fn default() -> Self {
        IprevOutput {
            result: IprevResult::None,
            ptr: None,
        }
    }
}

/// Alias for [`IprevOutput`].
pub type IprevEvaluationOutput = IprevOutput;

/// Alias for [`IprevOutput`].
pub type IprevTransactionOutput = IprevOutput;

/// The forward resolution of one PTR name, as observed by an `iprev` check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IprevForward {
    /// The PTR name that was resolved.
    pub name: Box<str>,
    /// The A or AAAA addresses returned for `name`. Empty when the lookup
    /// failed or returned no records.
    pub addresses: Arc<[IpAddr]>,
    /// The lookup error, or `None` when the lookup succeeded.
    pub error: Option<Error>,
    /// Whether `addresses` contains the client address that was checked.
    pub matched: bool,
}

impl IprevForward {
    /// Returns the PTR name that was resolved.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the A or AAAA addresses returned for the name.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the A or AAAA addresses returned for the name.
    pub fn records(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the A or AAAA addresses returned for the name.
    pub fn response(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the lookup error, or `None` when the lookup succeeded.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// Returns `true` when the response contains the checked client address.
    pub fn matched(&self) -> bool {
        self.matched
    }
}

impl Default for IprevForward {
    fn default() -> Self {
        IprevForward {
            name: String::new().into_boxed_str(),
            addresses: Arc::from(Vec::<IpAddr>::new()),
            error: None,
            matched: false,
        }
    }
}

/// Alias for [`IprevForward`].
pub type IprevForwardOutput = IprevForward;

/// A snapshot of the identity fixed for one `iprev` transaction.
///
/// The report is attached to an [`IprevOutput`] returned by a verifier. It is
/// intentionally not part of [`IprevOutput`] equality or of its public
/// struct fields, so callers that build synthetic outputs keep working and
/// the historical output shape is preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IprevReport {
    /// The SMTP client address that was checked.
    pub client_ip: IpAddr,
    /// The PTR names observed for `client_ip`.
    pub ptr: Option<Arc<[Box<str>]>>,
    /// The A/AAAA responses observed for the PTR names.
    pub forward: Arc<[IprevForward]>,
    /// The opaque generation of the DNS cache used by the transaction.
    /// `0` when the check ran without a cache.
    pub cache_generation: u64,
    /// The unique generation of this identity transaction.
    pub generation: u64,
    /// How many attempts ran in this transaction.
    pub attempts: u32,
    /// The result of the last attempt.
    pub result: IprevResult,
}

impl Default for IprevReport {
    fn default() -> Self {
        IprevReport {
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ptr: None,
            forward: Arc::from(Vec::<IprevForward>::new()),
            cache_generation: 0,
            generation: 0,
            attempts: 0,
            result: IprevResult::None,
        }
    }
}

impl IprevReport {
    /// Returns the SMTP client address that was checked.
    pub fn client_ip(&self) -> IpAddr {
        self.client_ip
    }

    /// Returns the SMTP client address that was checked.
    pub fn remote_ip(&self) -> IpAddr {
        self.client_ip
    }

    /// Returns the SMTP client address that was checked.
    pub fn client_address(&self) -> IpAddr {
        self.client_ip
    }

    /// Returns the PTR names observed for the client address.
    pub fn ptr(&self) -> Option<&[Box<str>]> {
        self.ptr.as_deref()
    }

    /// Returns the PTR names observed for the client address.
    pub fn ptr_names(&self) -> Option<&[Box<str>]> {
        self.ptr.as_deref()
    }

    /// Returns the PTR names observed for the client address.
    pub fn ptr_set(&self) -> Option<&[Box<str>]> {
        self.ptr.as_deref()
    }

    /// Returns the A/AAAA responses observed for the PTR names.
    pub fn forward(&self) -> &[IprevForward] {
        &self.forward
    }

    /// Returns the A/AAAA responses observed for the PTR names.
    pub fn forward_results(&self) -> &[IprevForward] {
        &self.forward
    }

    /// Returns the A/AAAA responses observed for the PTR names.
    pub fn responses(&self) -> &[IprevForward] {
        &self.forward
    }

    /// Returns the opaque DNS cache generation fixed for the transaction.
    pub fn cache_generation(&self) -> u64 {
        self.cache_generation
    }

    /// Returns the unique generation of the transaction.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the unique generation of the transaction.
    pub fn transaction_generation(&self) -> u64 {
        self.generation
    }

    /// Returns how many attempts ran in the transaction.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the result of the last attempt.
    pub fn result(&self) -> &IprevResult {
        &self.result
    }
}

/// Alias for [`IprevReport`], matching the terminology used by the SPF
/// evaluation report.
pub type IprevEvaluationReport = IprevReport;

/// Alias for [`IprevReport`].
pub type IprevTransactionReport = IprevReport;

/// Alias for [`IprevReport`].
pub type IprevIdentityReport = IprevReport;

/// An `iprev` result code, as defined in RFC 8601 Section 3.
///
/// The error carried by the failure variants explains the result and is
/// written as a comment in the `Authentication-Results` header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IprevResult {
    /// A PTR name resolved back to the client IP address.
    Pass,
    /// The PTR names were found, but none of them resolved back to the client
    /// IP address. Carries [`Error::NotAligned`].
    Fail(crate::Error),
    /// A DNS lookup failed with a transient error ([`DnsError::Resolver`]).
    /// The check may succeed if retried later.
    TempError(crate::Error),
    /// A DNS lookup failed permanently: no PTR record exists, a name was
    /// malformed or a forward lookup returned no records.
    PermError(crate::Error),
    /// No `iprev` check was performed. [`MessageAuthenticator::verify_iprev`]
    /// never returns this variant.
    None,
}

impl Default for IprevResult {
    fn default() -> Self {
        IprevResult::None
    }
}

impl MessageAuthenticator {
    /// Verifies the reverse DNS of an SMTP client IP address (RFC 8601
    /// Section 3).
    ///
    /// `params` is the client IP address, either alone or wrapped in
    /// [`Parameters`] together with a DNS cache.
    ///
    /// The check performs these DNS lookups:
    ///
    /// 1. A PTR query for the IP address.
    /// 2. For each of the first two names returned, an A query (IPv4 client)
    ///    or AAAA query (IPv6 client).
    ///
    /// The result is:
    ///
    /// - [`IprevResult::Pass`] as soon as a forward lookup returns the client
    ///   address. A lookup that failed before that match makes the result a
    ///   temporary or permanent error instead, because the matching answer
    ///   cannot be attributed to a fully completed transaction. Lookups after
    ///   a match do not invalidate it.
    /// - [`IprevResult::Fail`] with [`Error::NotAligned`] when every forward
    ///   lookup succeeded but none returned the client address, or when the PTR
    ///   answer was empty.
    /// - [`IprevResult::TempError`] or [`IprevResult::PermError`] when the PTR
    ///   lookup failed, or when no forward lookup matched and at least one of
    ///   them failed. Resolver errors ([`DnsError::Resolver`]) are temporary;
    ///   all other errors are permanent. The error of the last failed lookup is
    ///   reported.
    ///
    /// [`IprevOutput::ptr`] holds the PTR names whenever the PTR lookup
    /// succeeded.
    ///
    /// The client address, PTR set, forward answers and cache generation are
    /// fixed together. An incomplete transaction does not publish the PTR or
    /// A/AAAA answers collected by the aborted attempt to the shared cache.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{AuthenticationResults, IprevResult, MessageAuthenticator};
    /// use std::net::IpAddr;
    ///
    /// # async fn run() {
    /// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
    /// let remote_ip: IpAddr = "192.0.2.10".parse().unwrap();
    ///
    /// let iprev = authenticator.verify_iprev(remote_ip).await;
    /// if iprev.result() == &IprevResult::Pass {
    ///     println!("PTR names: {:?}", iprev.ptr);
    /// }
    ///
    /// let header = AuthenticationResults::new("mx.example.org")
    ///     .with_iprev_result(&iprev, remote_ip)
    ///     .to_string();
    /// # }
    /// ```
    pub async fn verify_iprev<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        let evaluation = IprevEvaluation::new();
        self.verify_iprev_with(params, &evaluation).await
    }

    /// Runs [`verify_iprev`](Self::verify_iprev) as a resumable identity
    /// transaction.
    ///
    /// Reusing the evaluation for the same client address keeps the frozen
    /// PTR set, cache generation and transaction generation. A different
    /// client address starts a new transaction on the same object, so a
    /// response observed for another SMTP hop can never be reused for this
    /// one. A transient failure leaves the transaction resumable; a completed
    /// transaction returns its frozen result on later calls. If the shared
    /// cache generation changed before a retry, the retry reports a temporary
    /// error instead of mixing answers from two generations; start a new
    /// evaluation to use the new cache contents.
    pub async fn verify_iprev_with<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
        evaluation: &IprevEvaluation,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        let cache_generation = params.cache_generation();
        let binding = evaluation.bind(params.input, cache_generation);
        if binding.completed
            && let Some(output) = evaluation.terminal_output(binding.generation)
        {
            return output;
        }
        if let Some(output) =
            evaluation.cache_generation_changed(binding.generation, cache_generation)
        {
            return output;
        }
        let transaction_generation = binding.generation;
        let transaction_cache_generation = binding.cache_generation;
        let transaction_attempts = binding.attempts;

        let client_ip = params.input;
        let generation_before = binding.cache_generation;

        let ptr_cache: Option<
            TransactionCache<'_, IpAddr, Result<RecordSet<Box<str>>, Negative>, C::Ptr>,
        > = params.ptr_cache().map(TransactionCache::new);
        let ipv4_cache: Option<
            TransactionCache<'_, Box<str>, Result<RecordSet<Ipv4Addr>, Negative>, C::Ipv4>,
        > = params.ipv4_cache().map(TransactionCache::new);
        let ipv6_cache: Option<
            TransactionCache<'_, Box<str>, Result<RecordSet<Ipv6Addr>, Negative>, C::Ipv6>,
        > = params.ipv6_cache().map(TransactionCache::new);

        let (ptr, ptr_error) = match evaluation.ptr_snapshot(transaction_generation) {
            Some(ptr) => (Some(ptr), None),
            None => match self.ptr_lookup(client_ip, ptr_cache.as_ref()).await {
                Ok(ptr) => (Some(ptr.records), None),
                Err(err) => (None, Some(err)),
            },
        };
        let ptr_failed = ptr_error.is_some();
        let mut forward = Vec::new();
        let mut last_error = None;
        let mut error_seen = false;
        let mut valid_match = false;

        if let Some(ptr) = ptr.as_ref() {
            for host in ptr.iter().take(2) {
                let (addresses, error, forward_matched) = match client_ip {
                    IpAddr::V4(ip) => match self.ipv4_lookup(host, ipv4_cache.as_ref()).await {
                        Ok(records) => {
                            let forward_matched = records.records.iter().any(|addr| *addr == ip);
                            (
                                records
                                    .records
                                    .iter()
                                    .copied()
                                    .map(IpAddr::from)
                                    .collect::<Vec<_>>(),
                                None,
                                forward_matched,
                            )
                        }
                        Err(err) => (Vec::new(), Some(err), false),
                    },
                    IpAddr::V6(ip) => match self.ipv6_lookup(host, ipv6_cache.as_ref()).await {
                        Ok(records) => {
                            let forward_matched = records.records.iter().any(|addr| *addr == ip);
                            (
                                records
                                    .records
                                    .iter()
                                    .copied()
                                    .map(IpAddr::from)
                                    .collect::<Vec<_>>(),
                                None,
                                forward_matched,
                            )
                        }
                        Err(err) => (Vec::new(), Some(err), false),
                    },
                };

                if let Some(err) = error.as_ref() {
                    last_error = Some((*err).clone());
                    error_seen = true;
                }
                if forward_matched && !error_seen {
                    valid_match = true;
                }
                forward.push(IprevForward {
                    name: (*host).clone(),
                    addresses: addresses.into(),
                    error,
                    matched: forward_matched,
                });
                if valid_match {
                    // As in the historical implementation, the first
                    // aligned name ends the check. Names after it cannot be
                    // used to weaken a result that is already established.
                    break;
                }
            }
        }

        let generation_after = params.cache_generation();
        let generation_changed = generation_before != generation_after;

        let result = if generation_changed {
            IprevResult::TempError(cache_generation_changed_error())
        } else if valid_match {
            IprevResult::Pass
        } else if let Some(err) = ptr_error {
            err.into()
        } else if let Some(err) = last_error {
            err.into()
        } else {
            IprevResult::Fail(Error::NotAligned)
        };

        // Only a transaction that observed one cache generation and
        // completed every lookup publishes its answers. An aborted attempt
        // must not leave a PTR set or A/AAAA answer behind for another
        // message to borrow.
        let complete = !ptr_failed
            && !generation_changed
            && forward.iter().all(|forward| forward.error.is_none());
        if complete {
            if let Some(cache) = ptr_cache.as_ref() {
                cache.commit();
            }
            if let Some(cache) = ipv4_cache.as_ref() {
                cache.commit();
            }
            if let Some(cache) = ipv6_cache.as_ref() {
                cache.commit();
            }
        }

        let report = IprevReport {
            client_ip,
            ptr,
            forward: forward.into(),
            cache_generation: transaction_cache_generation,
            generation: transaction_generation,
            attempts: transaction_attempts,
            result,
        };
        let output = output_from_report(report.clone());
        evaluation.finish(report);
        output
    }

    /// Alias for [`verify_iprev_with`](Self::verify_iprev_with).
    pub async fn verify_iprev_transaction<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
        transaction: &IprevEvaluation,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        self.verify_iprev_with(params, transaction).await
    }

    /// Alias for [`verify_iprev_with`](Self::verify_iprev_with).
    pub async fn verify_iprev_with_transaction<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
        transaction: &IprevEvaluation,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        self.verify_iprev_with(params, transaction).await
    }

    /// Alias for [`verify_iprev_with`](Self::verify_iprev_with).
    pub async fn verify_iprev_evaluation<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
        evaluation: &IprevEvaluation,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        self.verify_iprev_with(params, evaluation).await
    }
}

impl From<IpAddr> for Parameters<'_, IpAddr, NoCache> {
    fn from(params: IpAddr) -> Self {
        Parameters::new(params)
    }
}

impl IprevOutput {
    /// Returns the `iprev` result.
    pub fn result(&self) -> &IprevResult {
        &self.result
    }

    /// Returns the identity snapshot of the verification that produced this
    /// output.
    ///
    /// Returns `None` for an `IprevOutput` built by hand rather than returned
    /// by a verifier.
    pub fn report(&self) -> Option<IprevReport> {
        self.ptr.as_ref().and_then(|ptr| lookup_report(ptr))
    }

    /// Alias for [`report`](Self::report).
    pub fn transaction(&self) -> Option<IprevReport> {
        self.report()
    }

    /// Alias for [`report`](Self::report).
    pub fn evaluation(&self) -> Option<IprevReport> {
        self.report()
    }

    /// Alias for [`report`](Self::report).
    pub fn identity(&self) -> Option<IprevReport> {
        self.report()
    }

    /// Alias for [`report`](Self::report).
    pub fn iprev_report(&self) -> Option<IprevReport> {
        self.report()
    }

    /// Alias for [`report`](Self::report).
    pub fn identity_report(&self) -> Option<IprevReport> {
        self.report()
    }

    /// Returns the client address checked by the verification, if known.
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.report().map(|report| report.client_ip)
    }

    /// Returns the client address checked by the verification, if known.
    pub fn remote_ip(&self) -> Option<IpAddr> {
        self.client_ip()
    }

    /// Returns the client address checked by the verification, if known.
    pub fn client_address(&self) -> Option<IpAddr> {
        self.client_ip()
    }

    /// Returns the PTR names fixed for the verification.
    pub fn ptr_names(&self) -> Option<Arc<[Box<str>]>> {
        self.report().and_then(|report| report.ptr)
    }

    /// Returns the PTR names fixed for the verification.
    pub fn ptr_set(&self) -> Option<Arc<[Box<str>]>> {
        self.ptr_names()
    }

    /// Returns the A/AAAA responses fixed for the verification.
    pub fn forward_results(&self) -> Arc<[IprevForward]> {
        self.report()
            .map(|report| report.forward)
            .unwrap_or_else(|| Arc::from(Vec::<IprevForward>::new()))
    }

    /// Returns the A/AAAA responses fixed for the verification.
    pub fn forward(&self) -> Arc<[IprevForward]> {
        self.forward_results()
    }

    /// Returns the transaction generation, or `0` for a hand-built output.
    pub fn generation(&self) -> u64 {
        self.report().map(|report| report.generation).unwrap_or(0)
    }

    /// Returns the transaction generation, or `0` for a hand-built output.
    pub fn transaction_generation(&self) -> u64 {
        self.generation()
    }

    /// Returns the DNS cache generation, or `0` for a hand-built output.
    pub fn cache_generation(&self) -> u64 {
        self.report()
            .map(|report| report.cache_generation)
            .unwrap_or(0)
    }

    /// Returns the DNS cache generation, or `0` for a hand-built output.
    pub fn report_cache_generation(&self) -> u64 {
        self.cache_generation()
    }

    /// Returns the transaction generation, or `0` for a hand-built output.
    pub fn report_generation(&self) -> u64 {
        self.generation()
    }

    /// Returns how many attempts ran in the transaction.
    pub fn attempts(&self) -> u32 {
        self.report().map(|report| report.attempts).unwrap_or(0)
    }
}

impl From<Error> for IprevResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            IprevResult::TempError(err)
        } else {
            IprevResult::PermError(err)
        }
    }
}

fn cache_generation_changed_error() -> Error {
    Error::Dns(DnsError::Resolver(
        "DNS cache generation changed during the iprev transaction".to_string(),
    ))
}

impl Display for IprevResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IprevResult::Pass => f.write_str("pass"),
            IprevResult::Fail(err) => write!(f, "fail; {err}"),
            IprevResult::TempError(err) => write!(f, "temp error; {err}"),
            IprevResult::PermError(err) => write!(f, "perm error; {err}"),
            IprevResult::None => f.write_str("none"),
        }
    }
}

static NEXT_IPREV_GENERATION: AtomicUsize = AtomicUsize::new(1);

fn next_iprev_generation() -> u64 {
    NEXT_IPREV_GENERATION
        .fetch_add(1, Ordering::Relaxed)
        .max(1) as u64
}

#[derive(Debug)]
struct IprevEvaluationState {
    generation: u64,
    cache_generation: u64,
    client_ip: Option<IpAddr>,
    ptr: Option<Arc<[Box<str>]>>,
    forward: Arc<[IprevForward]>,
    attempts: u32,
    completed: bool,
    last_report: Option<IprevReport>,
}

#[derive(Debug, Clone, Copy)]
struct IprevBinding {
    generation: u64,
    cache_generation: u64,
    attempts: u32,
    completed: bool,
}

/// Resumable state for one `iprev` identity transaction.
///
/// [`verify_iprev`](MessageAuthenticator::verify_iprev) creates a new value for
/// every check. Use
/// [`verify_iprev_with`](MessageAuthenticator::verify_iprev_with) with the
/// same value to retry the same client address. The evaluation freezes the
/// PTR set, cache generation and transaction generation, so a retry cannot
/// borrow a PTR set or forward answer observed for another SMTP hop.
///
/// Cloning is intentionally not implemented: each evaluation has its own
/// mutable state and must not silently diverge into two transactions.
pub struct IprevEvaluation {
    state: Mutex<IprevEvaluationState>,
}

/// Alias for [`IprevEvaluation`].
pub type IprevTransaction = IprevEvaluation;

/// Alias for [`IprevEvaluation`].
pub type IprevIdentity = IprevEvaluation;

/// Alias for [`IprevEvaluation`].
pub type IprevVerification = IprevEvaluation;

impl Default for IprevEvaluation {
    fn default() -> Self {
        Self::new()
    }
}

impl IprevEvaluation {
    /// Creates an unused evaluation. The first check that binds it fixes its
    /// client address and cache generation.
    pub fn new() -> Self {
        IprevEvaluation {
            state: Mutex::new(IprevEvaluationState {
                generation: next_iprev_generation(),
                cache_generation: 0,
                client_ip: None,
                ptr: None,
                forward: Arc::from(Vec::<IprevForward>::new()),
                attempts: 0,
                completed: false,
                last_report: None,
            }),
        }
    }

    /// Returns the unique generation of the current transaction.
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Returns the unique generation of the current transaction.
    pub fn transaction_generation(&self) -> u64 {
        self.generation()
    }

    /// Returns the opaque DNS cache generation fixed when the transaction
    /// started. It is `0` when no cache was used.
    pub fn cache_generation(&self) -> u64 {
        self.lock_state().cache_generation
    }

    /// Returns the client address bound to the transaction, if any.
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.lock_state().client_ip
    }

    /// Returns the PTR names frozen for the transaction, if the PTR lookup
    /// has succeeded.
    pub fn ptr(&self) -> Option<Arc<[Box<str>]>> {
        self.lock_state().ptr.clone()
    }

    /// Returns the A/AAAA responses of the last attempt.
    pub fn forward(&self) -> Arc<[IprevForward]> {
        self.lock_state().forward.clone()
    }

    /// Returns how many attempts ran in the current transaction.
    pub fn attempts(&self) -> u32 {
        self.lock_state().attempts
    }

    /// Returns the result of the last attempt, if any.
    pub fn result(&self) -> Option<IprevResult> {
        self.lock_state()
            .last_report
            .as_ref()
            .map(|report| report.result.clone())
    }

    /// Returns the report of the last attempt, if any.
    pub fn report(&self) -> Option<IprevReport> {
        self.lock_state().last_report.clone()
    }

    fn bind(&self, client_ip: IpAddr, cache_generation: u64) -> IprevBinding {
        let mut state = self.lock_state();
        if state.client_ip != Some(client_ip) {
            state.generation = next_iprev_generation();
            state.cache_generation = cache_generation;
            state.client_ip = Some(client_ip);
            state.ptr = None;
            state.forward = Arc::from(Vec::<IprevForward>::new());
            state.attempts = 1;
            state.completed = false;
            state.last_report = None;
        } else {
            state.attempts = state.attempts.saturating_add(1);
        }
        IprevBinding {
            generation: state.generation,
            cache_generation: state.cache_generation,
            attempts: state.attempts,
            completed: state.completed,
        }
    }

    fn ptr_snapshot(&self, generation: u64) -> Option<Arc<[Box<str>]>> {
        let state = self.lock_state();
        if state.generation == generation {
            state.ptr.clone()
        } else {
            None
        }
    }

    fn cache_generation_changed(&self, generation: u64, current: u64) -> Option<IprevOutput> {
        let mut state = self.lock_state();
        if state.generation != generation {
            return None;
        }
        let client_ip = state.client_ip?;
        if state.completed || state.cache_generation == current || state.ptr.is_none() {
            return None;
        }
        let report = IprevReport {
            client_ip,
            ptr: state.ptr.clone(),
            forward: state.forward.clone(),
            cache_generation: state.cache_generation,
            generation: state.generation,
            attempts: state.attempts,
            result: IprevResult::TempError(cache_generation_changed_error()),
        };
        state.last_report = Some(report.clone());
        Some(output_from_report(report))
    }

    fn finish(&self, report: IprevReport) {
        let mut state = self.lock_state();
        if state.generation != report.generation || state.client_ip != Some(report.client_ip) {
            // A newer binding (another SMTP hop) owns the evaluation now.
            return;
        }
        state.ptr = report.ptr.clone();
        state.forward = report.forward.clone();
        // A transient failure remains resumable. Every other result freezes
        // the transaction, so a later cache recovery cannot upgrade or
        // relabel it for another message.
        state.completed = !matches!(report.result, IprevResult::TempError(_));
        state.last_report = Some(report);
    }

    fn terminal_output(&self, generation: u64) -> Option<IprevOutput> {
        let mut state = self.lock_state();
        if !state.completed || state.generation != generation {
            return None;
        }
        let mut report = state.last_report.clone()?;
        report.attempts = state.attempts;
        state.last_report = Some(report.clone());
        Some(output_from_report(report))
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, IprevEvaluationState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn output_from_report(mut report: IprevReport) -> IprevOutput {
    let ptr = report
        .ptr
        .as_ref()
        .map(|ptr| ptr.iter().cloned().collect::<Arc<[Box<str>]>>());
    report.ptr = ptr.clone();
    let output = IprevOutput {
        result: report.result.clone(),
        ptr: ptr.clone(),
    };
    if let Some(ptr) = ptr {
        register_report(&ptr, report);
    }
    output
}

#[derive(Clone)]
struct RegisteredReport {
    report: IprevReport,
}

static IPREV_REPORTS: OnceLock<Mutex<HashMap<usize, RegisteredReport>>> = OnceLock::new();

fn iprev_reports() -> &'static Mutex<HashMap<usize, RegisteredReport>> {
    IPREV_REPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn report_key(ptr: &Arc<[Box<str>]>) -> usize {
    Arc::as_ptr(ptr) as usize
}

fn register_report(ptr: &Arc<[Box<str>]>, report: IprevReport) {
    let mut reports = iprev_reports()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reports.retain(|_, entry| {
        entry
            .report
            .ptr
            .as_ref()
            .is_some_and(|ptr| Arc::strong_count(ptr) > 1)
    });
    reports.insert(
        report_key(ptr),
        RegisteredReport { report },
    );
}

fn lookup_report(ptr: &Arc<[Box<str>]>) -> Option<IprevReport> {
    let mut reports = iprev_reports()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reports.retain(|_, entry| {
        entry
            .report
            .ptr
            .as_ref()
            .is_some_and(|ptr| Arc::strong_count(ptr) > 1)
    });
    reports
        .get(&report_key(ptr))
        .filter(|entry| {
            entry
                .report
                .ptr
                .as_ref()
                .is_some_and(|entry_ptr| Arc::ptr_eq(entry_ptr, ptr))
        })
        .map(|entry| entry.report.clone())
}

/// A write-staging view of one shared DNS cache.
///
/// Reads fall through to the shared cache, while writes are kept in a
/// transaction-local buffer and published only when the whole `iprev` check
/// completes without a partial failure.
struct TransactionCache<'a, K, V, C: ResolverCache<K, V>> {
    shared: Option<&'a C>,
    staged: Mutex<Vec<(K, V, Instant)>>,
}

impl<'a, K, V, C: ResolverCache<K, V>> TransactionCache<'a, K, V, C> {
    fn new(shared: &'a C) -> Self {
        TransactionCache {
            shared: Some(shared),
            staged: Mutex::new(Vec::new()),
        }
    }

    fn commit(&self) {
        let Some(shared) = self.shared else {
            self.staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            return;
        };
        let staged = {
            let mut staged = self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *staged)
        };
        for (key, value, valid_until) in staged {
            shared.insert(key, value, valid_until);
        }
    }
}

impl<K, V, C> ResolverCache<K, V> for TransactionCache<'_, K, V, C>
where
    K: Clone + Hash + Eq,
    V: Clone,
    C: ResolverCache<K, V>,
{
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(value) = self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .rev()
            .find(|entry| <K as Borrow<Q>>::borrow(&entry.0) == name)
            .map(|entry| entry.1.clone())
        {
            return Some(value);
        }
        self.shared.and_then(|cache| cache.get(name))
    }

    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shared.and_then(|cache| cache.remove(name))
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = staged.iter_mut().find(|entry| entry.0 == key) {
            *entry = (key, value, valid_until);
        } else {
            staged.push((key, value, valid_until));
        }
    }

    fn generation(&self) -> u64 {
        self.shared.map(|cache| cache.generation()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{IprevEvaluation, IprevResult};
    use crate::{
        AuthenticationResults, MessageAuthenticator,
        dns::cache::test::DummyCaches,
    };
    use std::{
        net::IpAddr,
        time::{Duration, Instant},
    };

    fn caches() -> DummyCaches {
        DummyCaches::new()
    }

    fn valid_until() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[tokio::test]
    async fn iprev_ipv4_dual_ptr_and_auth_result_share_identity() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = caches();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        caches.ptr_add(
            ip,
            vec!["first.example.org.".into(), "second.example.org.".into()],
            valid_until(),
        );
        caches.ipv4_add(
            "first.example.org.",
            vec!["198.51.100.10".parse().unwrap()],
            valid_until(),
        );
        caches.ipv4_add(
            "second.example.org.",
            vec!["192.0.2.10".parse().unwrap()],
            valid_until(),
        );

        let iprev = resolver
            .verify_iprev(caches.parameters(ip))
            .await;
        assert_eq!(iprev.result(), &IprevResult::Pass);
        assert_eq!(iprev.client_ip(), Some(ip));
        assert_eq!(iprev.ptr.as_deref().unwrap().len(), 2);
        assert_eq!(iprev.forward_results().len(), 2);

        let auth = AuthenticationResults::new("mx.example.org")
            .with_iprev_result(&iprev, ip)
            .to_string();
        assert!(auth.contains("iprev=pass policy.iprev=192.0.2.10"));
    }

    #[tokio::test]
    async fn iprev_ipv6_dual_ptr() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = caches();
        let ip: IpAddr = "2001:db8::10".parse().unwrap();
        caches.ptr_add(
            ip,
            vec!["one.example.org.".into(), "two.example.org.".into()],
            valid_until(),
        );
        caches.ipv6_add(
            "one.example.org.",
            vec!["2001:db8::20".parse().unwrap()],
            valid_until(),
        );
        caches.ipv6_add(
            "two.example.org.",
            vec!["2001:db8::10".parse().unwrap()],
            valid_until(),
        );

        let iprev = resolver
            .verify_iprev(caches.parameters(ip))
            .await;
        assert_eq!(iprev.result(), &IprevResult::Pass);
        assert_eq!(iprev.client_ip(), Some(ip));
        let auth = AuthenticationResults::new("mx.example.org")
            .with_iprev_result(&iprev, ip)
            .to_string();
        assert!(auth.contains("iprev=pass policy.iprev=\"2001:db8::10\""));
    }

    #[tokio::test]
    async fn iprev_partial_forward_failure_does_not_pass() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = caches();
        let ip: IpAddr = "192.0.2.11".parse().unwrap();
        caches.ptr_add(
            ip,
            vec![
                "first._dns_error.example.org.".into(),
                "second.example.org.".into(),
            ],
            valid_until(),
        );
        caches.ipv4_add(
            "second.example.org.",
            vec!["192.0.2.11".parse().unwrap()],
            valid_until(),
        );

        let iprev = resolver
            .verify_iprev(caches.parameters(ip))
            .await;
        assert!(matches!(iprev.result(), IprevResult::TempError(_)));
        assert!(iprev.forward_results().iter().any(|forward| forward.matched));
        assert!(iprev.forward_results().iter().any(|forward| forward.error.is_some()));
    }

    #[tokio::test]
    async fn iprev_auth_result_refuses_another_hop_identity() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = caches();
        let ip: IpAddr = "192.0.2.12".parse().unwrap();
        caches.ptr_add(
            ip,
            vec!["mx.example.org.".into()],
            valid_until(),
        );
        caches.ipv4_add(
            "mx.example.org.",
            vec!["192.0.2.12".parse().unwrap()],
            valid_until(),
        );

        let iprev = resolver
            .verify_iprev(caches.parameters(ip))
            .await;
        assert_eq!(iprev.result(), &IprevResult::Pass);

        let other_ip: IpAddr = "192.0.2.13".parse().unwrap();
        let auth = AuthenticationResults::new("mx.example.org")
            .with_iprev_result(&iprev, other_ip)
            .to_string();
        assert!(auth.contains("iprev=none policy.iprev=192.0.2.13"));
        assert!(!auth.contains("iprev=pass"));
    }

    #[tokio::test]
    async fn iprev_retry_keeps_the_frozen_ptr_set() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = caches();
        let ip: IpAddr = "192.0.2.14".parse().unwrap();
        caches.ptr_add(
            ip,
            vec![
                "first._dns_error.example.org.".into(),
                "second.example.org.".into(),
            ],
            valid_until(),
        );
        caches.ipv4_add(
            "second.example.org.",
            vec!["192.0.2.99".parse().unwrap()],
            valid_until(),
        );

        let evaluation = IprevEvaluation::new();
        let first = resolver
            .verify_iprev_with(caches.parameters(ip), &evaluation)
            .await;
        assert!(matches!(first.result(), IprevResult::TempError(_)));
        let first_generation = first.generation();
        let first_cache_generation = first.cache_generation();
        assert_eq!(first.ptr.as_deref().unwrap().len(), 2);

        // A new PTR set and a matching A answer appear in the cache. The
        // retry of the same client address must not adopt either of them as
        // if they had been observed by the first transaction.
        caches.ptr_add(
            ip,
            vec!["previous-hop.example.org.".into()],
            valid_until(),
        );
        caches.ipv4_add(
            "previous-hop.example.org.",
            vec!["192.0.2.14".parse().unwrap()],
            valid_until(),
        );

        let second = resolver
            .verify_iprev_with(caches.parameters(ip), &evaluation)
            .await;
        assert!(matches!(
            second.result(),
            IprevResult::TempError(_) | IprevResult::PermError(_)
        ));
        assert_eq!(
            second
                .ptr
                .as_deref()
                .unwrap()
                .iter()
                .map(|name| &**name)
                .collect::<Vec<_>>(),
            vec!["first._dns_error.example.org.", "second.example.org."]
        );
        assert_eq!(second.generation(), first_generation);
        assert_eq!(second.cache_generation(), first_cache_generation);
        assert_eq!(second.attempts(), 2);
    }
}
