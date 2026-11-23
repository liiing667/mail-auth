/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub use super::SpfEvaluationReport;

use super::{Macro, Mechanism, Qualifier, SpfIdentity, SpfRecord, Variables};
use crate::DnsError;
use crate::Instant;
use crate::dns::{DnsCache, Negative, ToFqdn, has_valid_labels};
use crate::{
    Error, MessageAuthenticator, Parameters, RecordSet, ResolverCache, SpfOutput, SpfResult,
    dns::cache::NoCache,
};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Input of an SPF check: the client IP, the identity to check and the
/// values used for macro expansion.
///
/// Built with [`SpfParameters::helo`], [`SpfParameters::mail_from`],
/// [`SpfParameters::helo_and_mail_from`] or [`SpfParameters::new`], and
/// passed to [`MessageAuthenticator::verify_spf`] or
/// [`MessageAuthenticator::check_host`], optionally wrapped in [`Parameters`]
/// to supply a DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpfParameters<'x> {
    ip: IpAddr,
    domain: &'x str,
    helo_domain: &'x str,
    host_domain: &'x str,
    sender: Sender<'x>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sender<'x> {
    Helo,
    MailFrom(&'x str),
    Full(&'x str),
}

#[allow(clippy::iter_skip_zero)]
impl MessageAuthenticator {
    /// Verifies the SPF identities of an SMTP session (RFC 7208).
    ///
    /// With parameters built by [`SpfParameters::helo_and_mail_from`] (or
    /// [`SpfParameters::new`]), the HELO identity is checked first. Its output
    /// is returned when the result is `fail` or the sender is empty;
    /// otherwise the MAIL FROM identity is checked and its output returned.
    /// With parameters built by [`SpfParameters::helo`] or
    /// [`SpfParameters::mail_from`], a single [`check_host`] is run for that
    /// identity.
    ///
    /// HELO and MAIL FROM are separate `check_host()` evaluations, each with
    /// its own ten-lookup budget as required by RFC 7208. The output reports
    /// the source record, query budget, cache generation and qualifier of the
    /// identity whose result is returned. See [`SpfResult`] for the meaning
    /// of each result.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{MessageAuthenticator, SpfResult, spf::verify::SpfParameters};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator) {
    /// let output = authenticator
    ///     .verify_spf(SpfParameters::helo_and_mail_from(
    ///         "192.0.2.1".parse().unwrap(),
    ///         "mx.example.org",
    ///         "mx.my-host.org",
    ///         "sender@example.org",
    ///     ))
    ///     .await;
    ///
    /// if output.result() == SpfResult::Fail {
    ///     println!("rejected: {:?}", output.explanation());
    /// }
    /// # }
    /// ```
    ///
    /// [`check_host`]: MessageAuthenticator::check_host
    pub async fn verify_spf<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let evaluation = SpfEvaluation::new();
        self.verify_spf_with(params, &evaluation).await
    }

    /// Runs [`verify_spf`](Self::verify_spf) against a caller-owned
    /// [`SpfEvaluation`].
    ///
    /// HELO and MAIL FROM have different identities. Binding the evaluation
    /// to the second identity resets its budget and source variables, so the
    /// MAIL FROM check never reuses the HELO record or macro values.
    pub async fn verify_spf_with<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        match &params.input.sender {
            Sender::Full(sender) => {
                let helo_output = self
                    .check_host_with(
                        params.clone_with(SpfParameters::helo(
                            params.input.ip,
                            params.input.helo_domain,
                            params.input.host_domain,
                        )),
                        evaluation,
                    )
                    .await;
                if sender.is_empty() || helo_output.result() == SpfResult::Fail {
                    helo_output
                } else {
                    self.check_host_with(
                        params.clone_with(SpfParameters::mail_from(
                            params.input.ip,
                            params.input.helo_domain,
                            params.input.host_domain,
                            sender,
                        )),
                        evaluation,
                    )
                    .await
                }
            }
            _ => self.check_host_with(params, evaluation).await,
        }
    }

    /// Alias for [`verify_spf_with`](Self::verify_spf_with).
    pub async fn verify_spf_transaction<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        self.verify_spf_with(params, evaluation).await
    }

    /// Alias for [`verify_spf_with`](Self::verify_spf_with).
    pub async fn verify_spf_evaluation<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        self.verify_spf_with(params, evaluation).await
    }

    /// Runs the `check_host()` function (RFC 7208, Section 4) for a single
    /// identity.
    ///
    /// Evaluates the SPF record of the parameters' domain against the client
    /// IP. The DNS lookups performed are:
    ///
    /// - TXT for the `v=spf1` record of the domain, and of every `include:`
    ///   and `redirect=` target.
    /// - A or AAAA (depending on the client IP family) for the `a`, `mx`,
    ///   `ptr` and `exists` mechanisms.
    /// - MX for the `mx` mechanism.
    /// - PTR for the `ptr` mechanism and the `p` macro.
    /// - TXT for the `exp=` explanation, only on a `fail` result.
    ///
    /// The number of DNS-querying mechanisms and modifiers is limited to 10
    /// and the whole evaluation to 20 seconds; an `mx` mechanism may resolve
    /// at most 10 exchanges. Exceeding a limit yields `permerror`.
    ///
    /// The returned [`SpfOutput`] holds one of:
    ///
    /// - [`SpfResult::None`]: the domain is not a valid name or publishes no
    ///   SPF record.
    /// - [`SpfResult::Pass`], [`SpfResult::Fail`], [`SpfResult::SoftFail`] or
    ///   [`SpfResult::Neutral`]: the qualifier of the first matching
    ///   directive, or `neutral` when none matches.
    /// - [`SpfResult::TempError`]: a DNS lookup failed transiently.
    /// - [`SpfResult::PermError`]: a record could not be parsed, an
    ///   `include:` or `redirect=` target has no record, or a limit was
    ///   exceeded.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{MessageAuthenticator, spf::verify::SpfParameters};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator) {
    /// let output = authenticator
    ///     .check_host(SpfParameters::new(
    ///         "192.0.2.1".parse().unwrap(),
    ///         "example.org",
    ///         "mx.example.org",
    ///         "mx.my-host.org",
    ///         "sender@example.org",
    ///     ))
    ///     .await;
    /// println!("spf={} domain={}", output.result(), output.domain());
    /// # }
    /// ```
    #[allow(clippy::while_let_on_iterator)]
    #[allow(clippy::iter_skip_zero)]
    pub async fn check_host<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let evaluation = SpfEvaluation::new();
        self.check_host_with(params, &evaluation).await
    }

    /// Runs [`check_host`](Self::check_host) against a caller-owned
    /// [`SpfEvaluation`].
    ///
    /// Reusing the evaluation for a retry keeps the ten-query budget, the
    /// twenty second deadline, the source record and the cache generation
    /// observed by the first attempt. A different client IP, domain or
    /// identity starts a new evaluation on the same object.
    pub async fn check_host_with<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        evaluation.bind(
            SpfEvaluationIdentity::from_params(&params),
            params.cache_generation(),
        );
        let output = self.check_host_eval(params, evaluation).await;
        evaluation.finish(&output);
        output.with_evaluation(evaluation.build_report(output.result()))
    }

    /// Alias for [`check_host_with`](Self::check_host_with).
    pub async fn check_host_transaction<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        self.check_host_with(params, evaluation).await
    }

    /// Alias for [`check_host_with`](Self::check_host_with).
    pub async fn check_host_evaluation<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        self.check_host_with(params, evaluation).await
    }

    async fn check_host_eval<'x, C>(
        &self,
        params: Parameters<'x, SpfParameters<'x>, C>,
        evaluation: &SpfEvaluation,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let domain = params.input.domain;
        let ip = params.input.ip;
        let helo_domain = params.input.helo_domain;
        let host_domain = params.input.host_domain;
        let (sender, identity) = match &params.input.sender {
            Sender::Helo => ("", SpfIdentity::Helo),
            Sender::MailFrom(sender) | Sender::Full(sender) => (*sender, SpfIdentity::MailFrom),
        };

        let output = SpfOutput::new(domain.to_string()).with_identity(identity);
        if domain.is_empty() || domain.len() > 255 || !has_valid_labels(domain) {
            return output.with_result(SpfResult::None);
        }
        if let Some(result) = evaluation.terminal_result() {
            evaluation.note_attempt();
            return output.with_result(result);
        }
        evaluation.start_check(domain);
        evaluation.note_dns_name(domain);
        let postmaster;
        let sender = if sender.is_empty() {
            postmaster = postmaster_at(domain);
            postmaster.as_str()
        } else {
            sender
        };
        let mut vars = Variables::new();
        let mut has_p_var = false;
        vars.set_ip(&ip);
        vars.set_sender(sender.as_bytes());
        vars.set_domain(domain.as_bytes());
        vars.set_host_domain(host_domain.as_bytes());
        vars.set_helo_domain(helo_domain.as_bytes());

        let mut spf_record = match self
            .txt_lookup::<SpfRecord>(domain, params.txt_cache())
            .await
        {
            Ok(spf_record) => spf_record,
            Err(err) => return output.with_result(err.into()),
        };

        let mut domain = Cow::Borrowed(domain);
        let mut include_stack = Vec::new();

        let mut result = None;
        let mut directives = spf_record.directives.iter().enumerate().skip(0);

        loop {
            while result.is_none() {
                let Some((pos, directive)) = directives.next() else {
                    break;
                };
                if !has_p_var && directive.mechanism.needs_ptr() {
                    if !evaluation.can_lookup() {
                        return output
                            .with_result(SpfResult::PermError)
                            .with_report(&spf_record);
                    }
                    evaluation.note_dns_key(&ip.to_string());
                    match self.ptr_lookup(ip, params.ptr_cache()).await {
                        Ok(ptrs) => {
                            if let Some(ptr) = ptrs.records.first() {
                                vars.set_validated_domain(ptr.as_bytes().to_vec());
                            } else {
                                // RFC 7208 Section 7.3: a missing validated
                                // domain expands the `p` macro to "unknown".
                                vars.set_validated_domain(b"unknown".to_vec());
                            }
                            has_p_var = true;
                        }
                        Err(Error::Dns(DnsError::RecordNotFound(_)))
                        | Err(Error::Dns(DnsError::InvalidRecordType)) => {
                            vars.set_validated_domain(b"unknown".to_vec());
                            has_p_var = true;
                        }
                        Err(_) => {
                            return output
                                .with_result(SpfResult::TempError)
                                .with_report(&spf_record);
                        }
                    }
                }

                let matches = match &directive.mechanism {
                    Mechanism::All => true,
                    Mechanism::Ip4 { addr, mask } => ip.matches_ipv4_mask(addr, *mask),
                    Mechanism::Ip6 { addr, mask } => ip.matches_ipv6_mask(addr, *mask),
                    Mechanism::A {
                        macro_string,
                        ip4_mask,
                        ip6_mask,
                    } => {
                        if !evaluation.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }
                        let target_name = macro_string.eval(&vars, &domain, true);
                        evaluation.note_dns_name(target_name.as_ref());
                        match self
                            .ip_matches(
                                target_name.as_ref(),
                                ip,
                                *ip4_mask,
                                *ip6_mask,
                                params.ipv4_cache(),
                                params.ipv6_cache(),
                            )
                            .await
                        {
                            Ok(true) => true,
                            Ok(false) | Err(Error::Dns(DnsError::RecordNotFound(_))) => false,
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                    }
                    Mechanism::Mx {
                        macro_string,
                        ip4_mask,
                        ip6_mask,
                    } => {
                        if !evaluation.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let mut matches = false;
                        let target_name = macro_string.eval(&vars, &domain, true);
                        evaluation.note_dns_name(target_name.as_ref());
                        match self
                            .mx_lookup(target_name.as_ref(), params.mx_cache())
                            .await
                        {
                            Ok(records) => {
                                for (mx_num, exchange) in records
                                    .records
                                    .iter()
                                    .flat_map(|mx| mx.exchanges.iter())
                                    .enumerate()
                                {
                                    if mx_num > 9 {
                                        return output
                                            .with_result(SpfResult::PermError)
                                            .with_report(&spf_record);
                                    }

                                    match self
                                        .ip_matches(
                                            exchange,
                                            ip,
                                            *ip4_mask,
                                            *ip6_mask,
                                            params.ipv4_cache(),
                                            params.ipv6_cache(),
                                        )
                                        .await
                                    {
                                        Ok(true) => {
                                            matches = true;
                                            break;
                                        }
                                        Ok(false)
                                        | Err(Error::Dns(DnsError::RecordNotFound(_))) => (),
                                        Err(_) => {
                                            return output
                                                .with_result(SpfResult::TempError)
                                                .with_report(&spf_record);
                                        }
                                    }
                                }
                            }
                            Err(Error::Dns(DnsError::RecordNotFound(_))) => (),
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                        matches
                    }
                    Mechanism::Include { macro_string } => {
                        if !evaluation.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_name = macro_string.eval(&vars, &domain, true);
                        evaluation.note_dns_name(target_name.as_ref());
                        let included = self
                            .txt_lookup::<SpfRecord>(&*target_name, params.txt_cache())
                            .await;
                        match included {
                            Ok(included_spf) => {
                                let new_domain = target_name.into_owned();
                                include_stack.push((
                                    std::mem::replace(&mut spf_record, included_spf),
                                    pos,
                                    domain,
                                ));
                                directives = spf_record.directives.iter().enumerate().skip(0);
                                evaluation.set_source(&new_domain);
                                vars.set_domain(new_domain.as_bytes().to_vec());
                                domain = Cow::Owned(new_domain);
                                continue;
                            }
                            Err(
                                Error::Dns(DnsError::RecordNotFound(_))
                                | Error::Dns(DnsError::InvalidRecordType)
                                | Error::Parse,
                            ) => {
                                return output
                                    .with_result(SpfResult::PermError)
                                    .with_report(&spf_record);
                            }
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                    }
                    Mechanism::Ptr { macro_string } => {
                        if !evaluation.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_name = macro_string.eval(&vars, &domain, true);
                        let target_addr = to_lowercase(target_name.as_ref());
                        let target_addr = target_addr
                            .strip_suffix('.')
                            .unwrap_or(target_addr.as_ref());
                        let mut matches = false;

                        evaluation.note_dns_key(&ip.to_string());
                        match self.ptr_lookup(ip, params.ptr_cache()).await {
                            Ok(records) => {
                                for record in records.records.iter() {
                                    if evaluation.can_lookup() {
                                        evaluation.note_dns_name(record);
                                        if let Ok(true) = self
                                            .ip_matches(
                                                record,
                                                ip,
                                                u32::MAX,
                                                u128::MAX,
                                                params.ipv4_cache(),
                                                params.ipv6_cache(),
                                            )
                                            .await
                                        {
                                            let record = record
                                                .strip_suffix('.')
                                                .unwrap_or(record.as_ref());
                                            matches = record == target_addr
                                                || record
                                                    .strip_suffix(target_addr)
                                                    .is_some_and(|prefix| prefix.ends_with('.'));
                                            if matches {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(Error::Dns(DnsError::RecordNotFound(_)))
                            | Err(Error::Dns(DnsError::InvalidRecordType)) => (),
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                        matches
                    }
                    Mechanism::Exists { macro_string } => {
                        if !evaluation.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_name = macro_string.eval(&vars, &domain, true);
                        evaluation.note_dns_name(target_name.as_ref());
                        if let Ok(result) = self
                            .exists(
                                target_name.as_ref(),
                                params.ipv4_cache(),
                                params.ipv6_cache(),
                            )
                            .await
                        {
                            result
                        } else {
                            return output
                                .with_result(SpfResult::TempError)
                                .with_report(&spf_record);
                        }
                    }
                };

                if matches {
                    result = Some((&directive.qualifier).into());
                    break;
                }
            }

            if let (Some(macro_string), None) = (&spf_record.redirect, &result) {
                if !evaluation.can_lookup() {
                    return output
                        .with_result(SpfResult::PermError)
                        .with_report(&spf_record);
                }

                let target_name = macro_string.eval(&vars, &domain, true);
                evaluation.note_dns_name(target_name.as_ref());
                let redirect = self
                    .txt_lookup::<SpfRecord>(&*target_name, params.txt_cache())
                    .await;
                match redirect {
                    Ok(redirect_spf) => {
                        let new_domain = target_name.into_owned();
                        spf_record = redirect_spf;
                        directives = spf_record.directives.iter().enumerate().skip(0);
                        evaluation.set_source(&new_domain);
                        vars.set_domain(new_domain.as_bytes().to_vec());
                        domain = Cow::Owned(new_domain);
                        continue;
                    }
                    Err(
                        Error::Dns(DnsError::RecordNotFound(_))
                        | Error::Dns(DnsError::InvalidRecordType)
                        | Error::Parse,
                    ) => {
                        return output
                            .with_result(SpfResult::PermError)
                            .with_report(&spf_record);
                    }
                    Err(_) => {
                        return output
                            .with_result(SpfResult::TempError)
                            .with_report(&spf_record);
                    }
                }
            }

            if let Some((prev_record, prev_pos, prev_domain)) = include_stack.pop() {
                spf_record = prev_record;
                directives = spf_record.directives.iter().enumerate().skip(prev_pos);
                evaluation.set_source(prev_domain.as_ref());
                vars.set_domain(prev_domain.as_bytes().to_vec());
                domain = prev_domain;
                let qualifier = directives.next().map(|(_, directive)| &directive.qualifier);

                if matches!(result, Some(SpfResult::Pass)) {
                    if let Some(qualifier) = qualifier {
                        result = Some(qualifier.into());
                    }
                    // The nested include matched. Its result now propagates
                    // through the parent include directive, so continue
                    // popping frames until the root record or an include that
                    // does not match is reached.
                    continue;
                } else {
                    result = None;
                }
            } else {
                break;
            }
        }

        if let (Some(macro_string), Some(SpfResult::Fail)) = (&spf_record.exp, &result) {
            let target_name = macro_string.eval(&vars, &domain, true);
            evaluation.note_dns_name(target_name.as_ref());
            if let Ok(macro_string) = self
                .txt_lookup::<Macro>(target_name.as_ref(), params.txt_cache())
                .await
            {
                return output
                    .with_result(SpfResult::Fail)
                    .with_explanation(macro_string.eval(&vars, &domain, false).into_owned())
                    .with_report(&spf_record);
            }
        }

        output
            .with_result(result.unwrap_or(SpfResult::Neutral))
            .with_report(&spf_record)
    }

    async fn ip_matches(
        &self,
        target_name: &str,
        ip: IpAddr,
        ip4_mask: u32,
        ip6_mask: u128,
        cache_ipv4: Option<&impl ResolverCache<Box<str>, Result<RecordSet<Ipv4Addr>, Negative>>>,
        cache_ipv6: Option<&impl ResolverCache<Box<str>, Result<RecordSet<Ipv6Addr>, Negative>>>,
    ) -> crate::Result<bool> {
        Ok(match ip {
            IpAddr::V4(ip) => self
                .ipv4_lookup(target_name, cache_ipv4)
                .await?
                .records
                .iter()
                .any(|addr| ip.matches_ipv4_mask(addr, ip4_mask)),
            IpAddr::V6(ip) => self
                .ipv6_lookup(target_name, cache_ipv6)
                .await?
                .records
                .iter()
                .any(|addr| ip.matches_ipv6_mask(addr, ip6_mask)),
        })
    }
}

fn postmaster_at(domain: &str) -> String {
    const POSTMASTER: &str = "postmaster@";
    let mut sender = String::with_capacity(POSTMASTER.len() + domain.len());
    sender.push_str(POSTMASTER);
    sender.push_str(domain);
    sender
}

fn to_lowercase(value: &str) -> Cow<'_, str> {
    if value.is_ascii() {
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(value.to_ascii_lowercase())
        } else {
            Cow::Borrowed(value)
        }
    } else {
        Cow::Owned(value.to_lowercase())
    }
}

impl<'x> SpfParameters<'x> {
    /// Checks the HELO identity (RFC 7208, Section 2.3).
    ///
    /// The SPF record of `helo_domain` is evaluated with `<sender>` set to
    /// `postmaster@<helo_domain>`. `host_domain` is the name of the host
    /// performing the check (the `r` macro).
    pub fn helo(ip: IpAddr, helo_domain: &'x str, host_domain: &'x str) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: helo_domain,
            helo_domain,
            host_domain,
            sender: Sender::Helo,
        }
    }

    /// Checks the MAIL FROM identity (RFC 7208, Section 2.4).
    ///
    /// The SPF record of the domain of `sender` is evaluated; when `sender`
    /// has no `@`, `helo_domain` is used instead. An empty `sender` (null
    /// reverse-path) is replaced by `postmaster@<domain>`. `host_domain` is
    /// the name of the host performing the check (the `r` macro).
    pub fn mail_from(
        ip: IpAddr,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: sender.rsplit_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            host_domain,
            sender: Sender::MailFrom(sender),
        }
    }

    /// Checks the HELO identity and then, unless it fails, the MAIL FROM
    /// identity.
    ///
    /// Only [`MessageAuthenticator::verify_spf`] runs both checks; given to
    /// [`MessageAuthenticator::check_host`], these parameters check the MAIL
    /// FROM identity alone. Arguments are those of [`SpfParameters::mail_from`].
    pub fn helo_and_mail_from(
        ip: IpAddr,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: sender.rsplit_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            host_domain,
            sender: Sender::Full(sender),
        }
    }

    /// Parameters for [`MessageAuthenticator::check_host`].
    ///
    /// - `ip`: the SMTP client IP address (`<ip>`).
    /// - `domain`: the domain whose SPF record is evaluated (`<domain>`).
    /// - `helo_domain`: the domain given in the HELO or EHLO command.
    /// - `host_domain`: the name of the host performing the check (the `r` macro).
    /// - `sender`: the MAIL FROM address (`<sender>`); an empty string is
    ///   replaced by `postmaster@<domain>`.
    ///
    /// Given to [`MessageAuthenticator::verify_spf`], these parameters behave
    /// like [`SpfParameters::helo_and_mail_from`] and `domain` is ignored.
    pub fn new(
        ip: IpAddr,
        domain: &'x str,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> Self {
        SpfParameters {
            ip,
            domain,
            helo_domain,
            host_domain,
            sender: Sender::Full(sender),
        }
    }

    pub(crate) fn ip(&self) -> IpAddr {
        self.ip
    }

    pub(crate) fn helo_domain(&self) -> &'x str {
        self.helo_domain
    }

    pub(crate) fn host_domain(&self) -> &'x str {
        self.host_domain
    }

    pub(crate) fn mail_from_address(&self) -> Option<&'x str> {
        match self.sender {
            Sender::Helo => None,
            Sender::MailFrom(sender) | Sender::Full(sender) => Some(sender),
        }
    }
}

impl<'x> From<SpfParameters<'x>> for Parameters<'x, SpfParameters<'x>, NoCache> {
    fn from(params: SpfParameters<'x>) -> Self {
        Parameters::new(params)
    }
}

trait IpMask {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool;
    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool;
}

impl IpMask for IpAddr {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool {
        u32::from_be_bytes(match &self {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    ip.octets()
                } else {
                    return false;
                }
            }
        }) & mask
            == u32::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(match &self {
            IpAddr::V6(ip) => ip.octets(),
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        }) & mask
            == u128::from_be_bytes(addr.octets()) & mask
    }
}

impl IpMask for Ipv6Addr {
    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(self.octets()) & mask == u128::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv4_mask(&self, _addr: &Ipv4Addr, _mask: u32) -> bool {
        unimplemented!()
    }
}

impl IpMask for Ipv4Addr {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool {
        u32::from_be_bytes(self.octets()) & mask == u32::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv6_mask(&self, _addr: &Ipv6Addr, _mask: u128) -> bool {
        unimplemented!()
    }
}

impl From<&Qualifier> for SpfResult {
    fn from(q: &Qualifier) -> Self {
        match q {
            Qualifier::Pass => SpfResult::Pass,
            Qualifier::Fail => SpfResult::Fail,
            Qualifier::SoftFail => SpfResult::SoftFail,
            Qualifier::Neutral => SpfResult::Neutral,
        }
    }
}

impl From<Error> for SpfResult {
    fn from(err: Error) -> Self {
        match err {
            Error::Dns(DnsError::RecordNotFound(_)) | Error::Dns(DnsError::InvalidRecordType) => {
                SpfResult::None
            }
            Error::Parse => SpfResult::PermError,
            _ => SpfResult::TempError,
        }
    }
}

const SPF_QUERY_LIMIT: u32 = 10;
const SPF_EVALUATION_SECONDS: u64 = 20;

static NEXT_SPF_GENERATION: AtomicUsize = AtomicUsize::new(1);

fn next_spf_generation() -> u64 {
    NEXT_SPF_GENERATION
        .fetch_add(1, Ordering::Relaxed)
        .max(1) as u64
}

/// Identity of one resumable SPF evaluation.
///
/// Reusing a [`SpfEvaluation`] for the same identity keeps its budget. A
/// different IP, domain, sender or HELO name starts a new evaluation on the
/// same object, so unrelated checks cannot inherit a consumed budget.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpfEvaluationIdentity {
    ip: IpAddr,
    domain: Box<str>,
    sender_kind: u8,
    sender: Box<str>,
    helo_domain: Box<str>,
    host_domain: Box<str>,
}

impl SpfEvaluationIdentity {
    fn from_params<C: DnsCache>(params: &Parameters<'_, SpfParameters<'_>, C>) -> Self {
        let (sender_kind, sender): (u8, &str) = match &params.input.sender {
            Sender::Helo => (0, ""),
            Sender::MailFrom(sender) => (1, *sender),
            Sender::Full(sender) => (2, *sender),
        };

        SpfEvaluationIdentity {
            ip: params.input.ip,
            domain: params.input.domain.to_lowercase().into_boxed_str(),
            sender_kind,
            sender: sender.to_lowercase().into_boxed_str(),
            helo_domain: params.input.helo_domain.to_lowercase().into_boxed_str(),
            host_domain: params.input.host_domain.to_lowercase().into_boxed_str(),
        }
    }
}

#[derive(Debug)]
struct SpfEvaluationState {
    generation: u64,
    cache_generation: u64,
    lookups: u32,
    started: Instant,
    attempts: u32,
    source: Option<Box<str>>,
    dns_key: Option<Box<str>>,
    identity: Option<SpfEvaluationIdentity>,
    completed: bool,
    terminal: Option<SpfResult>,
    exhausted: bool,
    last_result: Option<SpfResult>,
}

/// Resumable state for one SPF evaluation.
///
/// [`check_host`](MessageAuthenticator::check_host) creates a new value for
/// each identity check. Use
/// [`check_host_with`](MessageAuthenticator::check_host_with) with the same
/// value to retry that identity. The evaluation freezes the query budget,
/// deadline, source record and cache generation, and exposes them through
/// [`SpfOutput::evaluation`](crate::spf::SpfOutput::evaluation).
///
/// Cloning is intentionally not implemented: each evaluation has its own
/// mutable state and must not silently diverge into two budgets.
#[derive(Debug)]
pub struct SpfEvaluation {
    state: Mutex<SpfEvaluationState>,
}

impl Default for SpfEvaluation {
    fn default() -> Self {
        Self::new()
    }
}

impl SpfEvaluation {
    /// Creates an unused evaluation. The first check that binds it fixes its
    /// generation and cache generation.
    pub fn new() -> Self {
        let now = Instant::now();
        SpfEvaluation {
            state: Mutex::new(SpfEvaluationState {
                generation: next_spf_generation(),
                cache_generation: 0,
                lookups: 1,
                started: now,
                attempts: 0,
                source: None,
                dns_key: None,
                identity: None,
                completed: false,
                terminal: None,
                exhausted: false,
                last_result: None,
            }),
        }
    }

    /// Returns the generation fixed for the current evaluation.
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Alias for [`SpfEvaluation::generation`].
    pub fn transaction_generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Returns the cache generation observed when the current evaluation
    /// started. It is `0` until a cache is bound and stays fixed across
    /// retries even if the cache recovers an answer.
    pub fn cache_generation(&self) -> u64 {
        self.lock_state().cache_generation
    }

    /// Returns how many attempts ran in the current evaluation.
    pub fn attempts(&self) -> u32 {
        self.lock_state().attempts
    }

    /// Returns how many DNS-querying mechanisms the evaluation has consumed.
    pub fn queries_used(&self) -> u32 {
        self.lock_state().lookups.saturating_sub(1)
    }

    /// Returns the number of DNS-querying mechanisms permitted by the
    /// evaluation.
    pub fn query_limit(&self) -> u32 {
        SPF_QUERY_LIMIT
    }

    /// Returns how many DNS-querying mechanisms remain in the evaluation.
    pub fn queries_remaining(&self) -> u32 {
        SPF_QUERY_LIMIT.saturating_sub(self.queries_used())
    }

    /// Returns the source record domain fixed by the last attempt.
    pub fn source(&self) -> Option<String> {
        self.lock_state()
            .source
            .as_ref()
            .map(|source| source.to_string())
    }

    /// Returns the last DNS key looked up by this evaluation.
    pub fn dns_key(&self) -> Option<String> {
        self.lock_state()
            .dns_key
            .as_ref()
            .map(|key| key.to_string())
    }

    /// Returns the last qualifier produced by this evaluation.
    pub fn qualifier(&self) -> Option<SpfResult> {
        self.lock_state().last_result
    }

    /// Alias for [`SpfEvaluation::qualifier`].
    pub fn result(&self) -> Option<SpfResult> {
        self.lock_state().last_result
    }

    /// Returns a report of the state fixed by the last completed attempt.
    pub fn last_report(&self) -> Option<SpfEvaluationReport> {
        let qualifier = self.lock_state().last_result?;
        Some(self.build_report(qualifier))
    }

    /// Returns a report of the state fixed by the last completed attempt.
    pub fn report(&self) -> Option<SpfEvaluationReport> {
        self.last_report()
    }

    fn bind(&self, identity: SpfEvaluationIdentity, cache_generation: u64) {
        let mut state = self.lock_state();
        let now = Instant::now();

        if !state.completed && state.identity.as_ref() == Some(&identity) {
            return;
        }

        state.generation = next_spf_generation();
        state.cache_generation = cache_generation;
        state.lookups = 1;
        state.started = now;
        state.attempts = 0;
        state.source = None;
        state.dns_key = None;
        state.identity = Some(identity);
        state.completed = false;
        state.terminal = None;
        state.exhausted = false;
        state.last_result = None;
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, SpfEvaluationState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn terminal_result(&self) -> Option<SpfResult> {
        self.lock_state().terminal
    }

    fn note_attempt(&self) {
        let mut state = self.lock_state();
        state.attempts = state.attempts.saturating_add(1);
    }

    fn start_check(&self, domain: &str) {
        let mut state = self.lock_state();
        state.attempts = state.attempts.saturating_add(1);
        state.source = Some(domain.into());
    }

    fn set_source(&self, source: &str) {
        let mut state = self.lock_state();
        state.source = Some(source.into());
    }

    fn note_dns_key(&self, key: &str) {
        let mut state = self.lock_state();
        state.dns_key = Some(key.into());
    }

    fn note_dns_name(&self, name: &str) {
        let fqdn = name.to_fqdn();
        self.note_dns_key(fqdn.as_ref());
    }

    #[inline(always)]
    fn can_lookup(&self) -> bool {
        let mut state = self.lock_state();
        if state.terminal.is_some() {
            state.exhausted = true;
            return false;
        }
        if state.lookups <= SPF_QUERY_LIMIT
            && state.started.elapsed().as_secs() < SPF_EVALUATION_SECONDS
        {
            state.lookups += 1;
            true
        } else {
            state.exhausted = true;
            false
        }
    }

    fn finish(&self, output: &SpfOutput) {
        let mut state = self.lock_state();
        state.last_result = Some(output.result());
        if output.result() == SpfResult::TempError {
            // A transient failure is resumable. Keep the consumed budget so a
            // retry or cache recovery cannot start with a fresh ten.
            return;
        }
        if output.result() == SpfResult::PermError
            && (state.exhausted || state.terminal.is_some())
        {
            state.terminal = Some(SpfResult::PermError);
        } else {
            state.completed = true;
            state.terminal = None;
        }
    }

    fn build_report(&self, qualifier: SpfResult) -> SpfEvaluationReport {
        let state = self.lock_state();
        SpfEvaluationReport {
            generation: state.generation,
            attempts: state.attempts,
            query_limit: SPF_QUERY_LIMIT,
            queries_used: state.lookups.saturating_sub(1),
            cache_generation: state.cache_generation,
            source: state.source.as_ref().map(|source| source.to_string()),
            dns_key: state.dns_key.as_ref().map(|key| key.to_string()),
            qualifier,
        }
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {

    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crate::{
        MessageAuthenticator, Mx, SpfResult,
        dns::cache::test::DummyCaches,
        parse::TxtRecordParser,
        spf::{Macro, SpfRecord},
    };

    use super::{SpfEvaluation, SpfParameters};

    #[tokio::test]
    async fn spf_verify() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("spf");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            println!("===== {} =====", file_name.display());
            let test_suite = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let caches = DummyCaches::new();

            for test in test_suite.split("---\n") {
                let mut test_name = "";
                let mut last_test_name = "";
                let mut helo = "";
                let mut mail_from = "";
                let mut client_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
                let mut test_num = 1;

                for line in test.split('\n') {
                    let line = line.trim();
                    let line = if let Some(line) = line.strip_prefix('-') {
                        line.trim()
                    } else {
                        line
                    };

                    if let Some(name) = line.strip_prefix("name:") {
                        test_name = name.trim();
                    } else if let Some(record) = line.strip_prefix("spf:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.txt_add(
                            name.trim().to_string(),
                            SpfRecord::parse(record.as_bytes()),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("exp:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.txt_add(
                            name.trim().to_string(),
                            Macro::parse(record.as_bytes()),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("a:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ipv4_add(
                            name.trim().to_string(),
                            record
                                .split(',')
                                .map(|item| item.trim().parse::<Ipv4Addr>().unwrap())
                                .collect(),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("aaaa:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ipv6_add(
                            name.trim().to_string(),
                            record
                                .split(',')
                                .map(|item| item.trim().parse::<Ipv6Addr>().unwrap())
                                .collect(),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("ptr:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ptr_add(
                            name.trim().parse::<IpAddr>().unwrap(),
                            record
                                .split(',')
                                .map(|item| Box::from(item.trim()))
                                .collect(),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("mx:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        let mut mxs = Vec::new();
                        for (pos, item) in record.split(',').enumerate() {
                            let ip = item.trim().parse::<IpAddr>().unwrap();
                            let mx_name = format!("mx.{ip}.{pos}");
                            match ip {
                                IpAddr::V4(ip) => {
                                    caches.ipv4_add(mx_name.clone(), vec![ip], valid_until)
                                }
                                IpAddr::V6(ip) => {
                                    caches.ipv6_add(mx_name.clone(), vec![ip], valid_until)
                                }
                            }
                            mxs.push(Mx {
                                exchanges: Box::new([mx_name.into_boxed_str()]),
                                preference: (pos + 1) as u16,
                            });
                        }
                        caches.mx_add(name.trim().to_string(), mxs, valid_until);
                    } else if let Some(value) = line.strip_prefix("domain:") {
                        helo = value.trim();
                    } else if let Some(value) = line.strip_prefix("sender:") {
                        mail_from = value.trim();
                    } else if let Some(value) = line.strip_prefix("ip:") {
                        client_ip = value.trim().parse().unwrap();
                    } else if let Some(value) = line.strip_prefix("expect:") {
                        let value = value.trim();
                        let (result, exp): (SpfResult, &str) =
                            if let Some((result, exp)) = value.split_once(' ') {
                                (result.trim().parse::<SpfResult>().unwrap(), exp.trim())
                            } else {
                                (value.parse::<SpfResult>().unwrap(), "")
                            };
                        let output = resolver
                            .verify_spf(caches.parameters(SpfParameters::helo_and_mail_from(
                                client_ip,
                                helo,
                                "localdomain.org",
                                mail_from,
                            )))
                            .await;
                        assert_eq!(
                            output.result(),
                            result,
                            "Failed for {test_name:?}, test {test_num}, ehlo: {helo}, mail-from: {mail_from}.",
                        );

                        if !exp.is_empty() {
                            assert_eq!(Some(exp.to_string()).as_deref(), output.explanation());
                        }
                        test_num += 1;
                        if test_name != last_test_name {
                            println!("Passed test {test_name:?}");
                            last_test_name = test_name;
                        }
                    }
                }
            }
        }
    }

    // A timeout must not turn a retry into a second ten-lookup budget. The
    // recovered include is intentionally unreachable: consuming the tenth
    // mechanism in the first attempt leaves no room for it when the same
    // evaluation is resumed.
    #[tokio::test]
    async fn retry_keeps_query_budget_and_source() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-retry-budget.test.org";
        let timeout_name = "spf-retry-inc10._dns_error.test.org";
        let mut record = String::from("v=spf1");
        for index in 0..9 {
            let name = format!("spf-retry-inc{index}.test.org");
            caches.txt_add(
                name.clone(),
                SpfRecord::parse(b"v=spf1 -all"),
                valid_until,
            );
            record.push_str(&format!(" include:{name}"));
        }
        record.push_str(&format!(" include:{timeout_name} -all"));
        caches.txt_add(root, SpfRecord::parse(record.as_bytes()), valid_until);

        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let sender = format!("sender@{root}");
        let params = SpfParameters::mail_from(ip, root, "mail.test.org", &sender);
        let evaluation = SpfEvaluation::new();

        let first = resolver
            .check_host_with(caches.parameters(params), &evaluation)
            .await;
        assert_eq!(first.result(), SpfResult::TempError);
        let first_report = first.evaluation().expect("first evaluation").clone();
        assert_eq!(first_report.queries_used(), 10);
        assert_eq!(first_report.query_limit(), 10);
        assert_eq!(first_report.source(), Some(root));
        assert_eq!(first_report.qualifier(), SpfResult::TempError);

        // Cache recovery makes the previously transient include available.
        caches.txt_add(timeout_name, SpfRecord::parse(b"v=spf1 +all"), valid_until);

        let second = resolver
            .check_host_with(caches.parameters(params), &evaluation)
            .await;
        assert_eq!(second.result(), SpfResult::PermError);
        let second_report = second.evaluation().expect("second evaluation");
        assert_eq!(second_report.generation(), first_report.generation());
        assert_eq!(second_report.queries_used(), first_report.queries_used());
        assert_eq!(second_report.query_limit(), first_report.query_limit());
        assert_eq!(second_report.source(), first_report.source());
        assert_eq!(second_report.cache_generation(), first_report.cache_generation());
        assert_eq!(second_report.qualifier(), SpfResult::PermError);
        assert_eq!(second_report.attempts(), 2);
    }

    // A transient error remains a real Temperror. If the cache recovers while
    // the evaluation still has budget, the retry may finish normally and must
    // keep the same generation, source and cache generation.
    #[tokio::test]
    async fn cache_recovery_resumes_same_evaluation() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-cache-recovery.test.org";
        let target = "spf-cache-recovery._dns_error.test.org";
        caches.txt_add(
            root,
            SpfRecord::parse(format!("v=spf1 include:{target} -all").as_bytes()),
            valid_until,
        );

        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let sender = format!("sender@{root}");
        let params = SpfParameters::mail_from(ip, root, "mail.test.org", &sender);
        let evaluation = SpfEvaluation::new();

        let first = resolver
            .check_host_with(caches.parameters(params), &evaluation)
            .await;
        assert_eq!(first.result(), SpfResult::TempError);
        let first_report = first.evaluation().expect("first evaluation").clone();
        assert_eq!(first_report.queries_used(), 1);

        caches.txt_add(target, SpfRecord::parse(b"v=spf1 +all"), valid_until);

        let second = resolver
            .check_host_with(caches.parameters(params), &evaluation)
            .await;
        assert_eq!(second.result(), SpfResult::Pass);
        let second_report = second.evaluation().expect("second evaluation");
        assert_eq!(second_report.generation(), first_report.generation());
        assert_eq!(second_report.source(), Some(root));
        assert_eq!(second_report.qualifier(), SpfResult::Pass);
        assert_eq!(second_report.cache_generation(), first_report.cache_generation());
        assert_eq!(second_report.attempts(), 2);
        assert_eq!(second_report.queries_used(), 2);
    }

    // HELO and MAIL FROM are separate check_host evaluations under RFC
    // 7208. A record that consumes all ten mechanisms must still be evaluated
    // with a fresh budget for the second identity, and the reported source,
    // budget and qualifier must describe that final identity.
    #[tokio::test]
    async fn verify_identities_keep_separate_budgets() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-verify-budget.test.org";

        let mut record = String::from("v=spf1");
        for index in 0..10 {
            let name = format!("spf-verify-inc{index}.test.org");
            caches.txt_add(
                name.clone(),
                SpfRecord::parse(b"v=spf1 -all"),
                valid_until,
            );
            record.push_str(&format!(" include:{name}"));
        }
        record.push_str(" ~all");
        caches.txt_add(root, SpfRecord::parse(record.as_bytes()), valid_until);

        let sender = format!("sender@{root}");
        let output = resolver
            .verify_spf(caches.parameters(SpfParameters::helo_and_mail_from(
                "192.168.1.5".parse().unwrap(),
                root,
                "mail.test.org",
                &sender,
            )))
            .await;

        assert_eq!(output.result(), SpfResult::SoftFail);
        let report = output.evaluation().expect("evaluation");
        assert_eq!(report.queries_used(), 10);
        assert_eq!(report.source(), Some(root));
        assert_eq!(report.qualifier(), SpfResult::SoftFail);
        assert_eq!(report.attempts(), 1);
    }

    // A matching include hands the nested `pass` back to the include
    // directive of the calling record. The result must be that directive's
    // qualifier, not the inner record's qualifier.
    #[tokio::test]
    async fn include_qualifier_belongs_to_the_calling_record() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-include-qualifier.test.org";
        caches.txt_add(
            "spf-include-middle.test.org",
            SpfRecord::parse(b"v=spf1 include:spf-include-inner.test.org"),
            valid_until,
        );
        caches.txt_add(
            "spf-include-inner.test.org",
            SpfRecord::parse(b"v=spf1 +all"),
            valid_until,
        );
        caches.txt_add(
            root,
            SpfRecord::parse(b"v=spf1 -include:spf-include-middle.test.org -all"),
            valid_until,
        );

        let sender = format!("sender@{root}");
        let output = resolver
            .check_host(caches.parameters(SpfParameters::mail_from(
                "192.168.1.5".parse().unwrap(),
                root,
                "mail.test.org",
                &sender,
            )))
            .await;

        assert_eq!(output.result(), SpfResult::Fail);
        let report = output.evaluation().expect("evaluation");
        assert_eq!(report.source(), Some(root));
        assert_eq!(report.qualifier(), SpfResult::Fail);
    }

    // The `p` macro is expanded from the client IP of the current identity,
    // and the resulting DNS key belongs to that expansion, not to a record
    // or macro value from another source.
    #[tokio::test]
    async fn validated_domain_macro_uses_the_current_source() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-p-macro.test.org";
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        caches.ptr_add(
            ip,
            vec![Box::<str>::from("ptr.spf-macro.example")],
            valid_until,
        );
        caches.txt_add(
            "spf.ptr.spf-macro.example.test.org",
            SpfRecord::parse(b"v=spf1 +all"),
            valid_until,
        );
        caches.txt_add(
            root,
            SpfRecord::parse(b"v=spf1 include:spf.%{p}.test.org -all"),
            valid_until,
        );

        let sender = format!("sender@{root}");
        let output = resolver
            .check_host(caches.parameters(SpfParameters::mail_from(
                ip,
                root,
                "mail.test.org",
                &sender,
            )))
            .await;

        assert_eq!(output.result(), SpfResult::Pass);
        let report = output.evaluation().expect("evaluation");
        assert_eq!(report.source(), Some(root));
        assert_eq!(report.qualifier(), SpfResult::Pass);
        assert_eq!(
            report.dns_key(),
            Some("spf.ptr.spf-macro.example.test.org.")
        );
    }

    // A propagated include result also restores the calling record's `%d`
    // before `exp=` is expanded, so the explanation comes from the record
    // that supplied the failing include qualifier.
    #[tokio::test]
    async fn explanation_uses_the_calling_record_domain() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let root = "spf-exp-source.test.org";
        caches.txt_add(
            "spf-exp-inner.test.org",
            SpfRecord::parse(b"v=spf1 +all"),
            valid_until,
        );
        let root_record =
            format!("v=spf1 -include:spf-exp-inner.test.org exp=explain.{root} -all");
        caches.txt_add(
            root,
            SpfRecord::parse(root_record.as_bytes()),
            valid_until,
        );
        caches.txt_add(
            format!("explain.{root}"),
            Macro::parse(format!("source={root} domain=%{{d}}").as_bytes()),
            valid_until,
        );

        let sender = format!("sender@{root}");
        let output = resolver
            .check_host(caches.parameters(SpfParameters::mail_from(
                "192.168.1.5".parse().unwrap(),
                root,
                "mail.test.org",
                &sender,
            )))
            .await;

        assert_eq!(output.result(), SpfResult::Fail);
        let expected = format!("source={root} domain={root}");
        assert_eq!(output.explanation(), Some(expected.as_str()));
        let report = output.evaluation().expect("evaluation");
        assert_eq!(report.source(), Some(root));
    }
}
