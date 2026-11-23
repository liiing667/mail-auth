/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Transactional authorization of external DMARC reporting destinations.
//!
//! One [`MessageAuthenticator::authorized_report_addresses`] call is one
//! authorization transaction: the policy domain, every report URI, its
//! external-authorization TXT record and the resulting decision all belong to
//! the same transaction. The answers consulted while checking the individual
//! destinations are staged in a private snapshot and are only published to
//! the shared TXT cache once every destination has been evaluated. A
//! transaction that aborts on a transient resolver error publishes nothing,
//! so a retry or a later transaction for another policy domain can never
//! borrow an authorization answer that belongs to a different set of
//! destinations.

use crate::{
    Instant,
    dns::{ResolverCache, TxtRecord},
};

/// Transactional context for one external-report authorization run.
///
/// The transaction owns the per-destination staging area of a single
/// [`MessageAuthenticator::authorized_report_addresses`] call. Reads reach
/// the entries staged earlier in this run and then fall through to the shared
/// cache; writes produced by a lookup are buffered until
/// [`commit`](Self::commit). Dropping the transaction without committing
/// discards the snapshot, which is what makes a transient failure (TempError)
/// leave the shared cache untouched.
pub(crate) struct ReportAuthorization<'a, C> {
    /// The shared application TXT cache the transaction publishes to once it
    /// completes, or `None` when caching is disabled.
    cache: Option<&'a C>,
    /// Answers (positive and cacheable negative) staged by the destination
    /// lookups performed during this transaction.
    staged: Vec<(Box<str>, TxtRecord, Instant)>,
}

impl<'a, C: ResolverCache<Box<str>, TxtRecord>> ReportAuthorization<'a, C> {
    /// Starts an authorization transaction over the supplied shared TXT
    /// cache (`None` means caching is disabled).
    pub(crate) fn new(cache: Option<&'a C>) -> Self {
        ReportAuthorization {
            cache,
            staged: Vec::new(),
        }
    }

    /// Wraps the shared cache in a per-transaction write gate for one
    /// destination lookup.
    pub(crate) fn gate(&mut self) -> AuthorizationCache<'_, C> {
        AuthorizationCache {
            shared: self.cache,
            staged: &mut self.staged,
        }
    }

    /// Publishes every answer staged by the just-finished transaction to the
    /// shared cache, preserving the TTL derived from each DNS answer.
    ///
    /// Entries already present in the shared cache (for example an
    /// authorization record seeded by the application or committed by an
    /// earlier, completed transaction) keep their existing value and TTL.
    pub(crate) fn commit(self) {
        let Some(cache) = self.cache else {
            return;
        };
        for (key, value, valid_until) in self.staged {
            if cache.get::<str>(&key).is_none() {
                cache.insert(key, value, valid_until);
            }
        }
    }
}

/// A write-gated view of the shared TXT cache used by one authorization
/// transaction.
///
/// It implements [`ResolverCache`], so the unmodified
/// [`MessageAuthenticator::txt_lookup`](crate::MessageAuthenticator::txt_lookup)
/// helper performs the parsing and the TTL calculation. Reads fall through to
/// the shared cache; writes are appended to the owning
/// [`ReportAuthorization`]'s staging buffer instead of touching the shared
/// cache before the transaction commits.
pub(crate) struct AuthorizationCache<'a, C> {
    /// The shared cache consulted for entries not staged in this
    /// transaction, or `None` when caching is disabled.
    shared: Option<&'a C>,
    /// The owning transaction's staging buffer.
    staged: &'a mut Vec<(Box<str>, TxtRecord, Instant)>,
}

impl<C: ResolverCache<Box<str>, TxtRecord>> ResolverCache<Box<str>, TxtRecord>
    for AuthorizationCache<'_, C>
{
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        if let Some((_, value, _)) = self
            .staged
            .iter()
            .rev()
            .find(|(key, _, _)| {
                let key_as_q: &Q = key.borrow();
                key_as_q == name
            })
        {
            return Some(value.clone());
        }
        self.shared.and_then(|cache| cache.get(name))
    }

    fn remove<Q>(&self, _name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        // Removal is never used by the lookup helpers; an authorization
        // transaction only ever inserts and must not mutate the shared cache
        // before it commits.
        None
    }

    fn insert(&self, key: Box<str>, value: TxtRecord, valid_until: Instant) {
        // Each authorization name is normally queried once, but keep one
        // entry per key anyway so the staged view matches ordinary cache
        // semantics within the transaction.
        if let Some(entry) = self
            .staged
            .iter_mut()
            .find(|(staged_key, _, _)| staged_key.as_ref() == key.as_ref())
        {
            *entry = (key, value, valid_until);
        } else {
            self.staged.push((key, value, valid_until));
        }
    }
}
