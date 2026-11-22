/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::DmarcParameters;
use crate::{
    AuthenticatedMessage, DkimOutput, DkimResult, DmarcResult, DnsError, Error,
    MessageAuthenticator, ResolverCache, SpfOutput, SpfResult, TxtRecord,
    dkim::{DkimError, Signature},
    dmarc::{DmarcRecord, Policy, Uri},
    dns::cache::test::DummyCaches,
    parse::TxtRecordParser,
};
use mail_parser::MessageParser;
use std::time::{Duration, Instant};

#[tokio::test]
async fn dmarc_verify_alignment() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();

    for (
        dmarc_dns,
        dmarc,
        message,
        mail_from_domain,
        signature_domain,
        dkim,
        spf,
        expect_dkim,
        expect_spf,
        policy,
    ) in [
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "example.org",
            "example.org",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=r; adkim=r; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            "subdomain.example.org",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            "subdomain.example.org",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Fail(Error::NotAligned),
            DmarcResult::Fail(Error::NotAligned),
            Policy::Reject,
        ),
        (
            "_dmarc.xn--eebajf.xn--9dbq2a.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@xn--eebajf.xn--9dbq2a",
            "From: hello@\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\r\n\r\n",
            "xn--eebajf.xn--9dbq2a",
            "xn--eebajf.xn--9dbq2a",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.xn--eebajf.xn--9dbq2a.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@xn--eebajf.xn--9dbq2a",
            "From: hello@xn--eebajf.xn--9dbq2a\r\n\r\n",
            "\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            "\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "example.org",
            "example.org",
            DkimResult::Fail(Error::Dkim(DkimError::SignatureExpired)),
            SpfResult::Fail,
            DmarcResult::None,
            DmarcResult::None,
            Policy::Reject,
        ),
    ] {
        caches.txt_add(
            dmarc_dns,
            DmarcRecord::parse(dmarc.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3200, 0),
        );

        let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
        let signature = Signature {
            d: signature_domain.into(),
            ..Default::default()
        };
        let dkim = DkimOutput {
            result: dkim,
            signature: (&signature).into(),
            report: None,
            is_atps: false,
        };
        let spf = SpfOutput {
            result: spf,
            domain: mail_from_domain.to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        let result = resolver
            .verify_dmarc(caches.parameters(DmarcParameters::new(
                &auth_message,
                &[dkim],
                mail_from_domain,
                &spf,
            )))
            .await;
        assert_eq!(result.dkim_result, expect_dkim, "dkim {message}");
        assert_eq!(result.spf_result, expect_spf, "spf {message}");
        assert_eq!(result.policy, policy, "policy {message}");
        let expect_result = if expect_dkim == DmarcResult::Pass || expect_spf == DmarcResult::Pass {
            DmarcResult::Pass
        } else {
            DmarcResult::Fail(Error::NotAligned)
        };
        assert_eq!(result.result(), expect_result, "result {message}");
    }
}

#[tokio::test]
async fn dmarc_policy_discovery() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let expires = Instant::now() + Duration::new(3200, 0);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@example.org").await,
        Policy::Reject,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    assert_eq!(
        policy_of(&resolver, &caches, "hello@sub.example.org").await,
        Policy::Quarantine,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@ghost.example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; rua=mailto:d@example.org").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; sp=reject; rua=mailto:d@example.org").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    assert_eq!(
        policy_of(&resolver, &caches, "hello@sub.example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; sp=reject; np=reject").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    let result = verify(&resolver, &caches, "hello@sub.example.org").await;
    assert_eq!(result.record(), None);
    assert_eq!(result.result(), DmarcResult::None);

    let caches = DummyCaches::new();
    let result = verify(&resolver, &caches, "hello@nothing.example").await;
    assert_eq!(result.record(), None);
    assert_eq!(result.result(), DmarcResult::None);
}

#[tokio::test]
async fn dmarc_verify_temp_errors() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(
            b"v=DMARC1; p=reject; rua=mailto:d@example.org; ruf=mailto:f@example.org",
        )
        .unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );
    let dns_error = Error::Dns(DnsError::Resolver("timeout".to_string()));
    let empty_dns_error = Error::Dns(DnsError::Resolver(String::new()));
    let auth_message = AuthenticatedMessage::parse(b"From: hello@example.org\r\n\r\n").unwrap();

    for (mail_from_domain, spf, signature_domain, dkim, expect_spf, expect_dkim, expect) in [
        (
            "example.org",
            SpfResult::TempError,
            "example.org",
            DkimResult::Fail(Error::Dkim(DkimError::BodyHashMismatch)),
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
        ),
        (
            "other.net",
            SpfResult::TempError,
            "other.net",
            DkimResult::TempError(dns_error.clone()),
            DmarcResult::None,
            DmarcResult::None,
            DmarcResult::Fail(Error::NotAligned),
        ),
        (
            "other.net",
            SpfResult::Fail,
            "example.org",
            DkimResult::TempError(dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(dns_error.clone()),
            DmarcResult::TempError(dns_error.clone()),
        ),
        (
            "example.org",
            SpfResult::TempError,
            "example.org",
            DkimResult::Pass,
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::Pass,
            DmarcResult::Pass,
        ),
        (
            "attacker._dns_error.net",
            SpfResult::Pass,
            "attacker._dns_error.net",
            DkimResult::Pass,
            DmarcResult::Fail(Error::NotAligned),
            DmarcResult::Fail(Error::NotAligned),
            DmarcResult::Fail(Error::NotAligned),
        ),
        (
            "sub._dns_error.example.org",
            SpfResult::Pass,
            "other.net",
            DkimResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
        ),
    ] {
        let signature = Signature {
            d: signature_domain.into(),
            ..Default::default()
        };
        let dkim = DkimOutput {
            result: dkim,
            signature: (&signature).into(),
            report: None,
            is_atps: false,
        };
        let spf = SpfOutput {
            result: spf,
            domain: mail_from_domain.to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        let result = resolver
            .verify_dmarc(caches.parameters(DmarcParameters::new(
                &auth_message,
                &[dkim],
                mail_from_domain,
                &spf,
            )))
            .await;
        let case = format!("{mail_from_domain} {signature_domain}");
        assert_eq!(result.spf_result, expect_spf, "spf {case}");
        assert_eq!(result.dkim_result, expect_dkim, "dkim {case}");
        assert_eq!(result.result(), expect, "result {case}");
        assert_eq!(
            result.failure_report().is_none(),
            matches!(expect, DmarcResult::TempError(_) | DmarcResult::Pass),
            "failure report {case}"
        );
    }
}

#[tokio::test]
async fn dmarc_tree_walk_psd() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let expires = Instant::now() + Duration::new(3200, 0);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.mail.example.com.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com").unwrap(),
        expires,
    );
    caches.ipv4_add("a.mail.example.com.", vec![[127, 0, 0, 1].into()], expires);
    let result = verify_aligned(
        &resolver,
        &caches,
        "hello@a.mail.example.com",
        "b.mail.example.com",
    )
    .await;
    assert_eq!(result.spf_result(), &DmarcResult::Pass);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.bank.example.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; psd=y; rua=mailto:d@bank.example").unwrap(),
        expires,
    );
    caches.txt_add(
        "_dmarc.giant.bank.example.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; rua=mailto:d@giant.bank.example").unwrap(),
        expires,
    );
    let result = verify_aligned(
        &resolver,
        &caches,
        "hello@giant.bank.example",
        "mega.bank.example",
    )
    .await;
    assert_eq!(result.spf_result(), &DmarcResult::Fail(Error::NotAligned));
}

#[tokio::test]
async fn dmarc_tree_walk_query_cap() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let expires = Instant::now() + Duration::new(3200, 0);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.com.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; np=none; rua=mailto:d@example.com").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(
            &resolver,
            &caches,
            "hello@a.b.c.d.e.f.g.h.i.j.mail.example.com",
        )
        .await,
        Policy::None,
    );
}

async fn verify(
    resolver: &MessageAuthenticator,
    caches: &DummyCaches,
    from: &str,
) -> DmarcOutputHelper {
    verify_aligned(resolver, caches, from, "").await
}

async fn verify_aligned(
    resolver: &MessageAuthenticator,
    caches: &DummyCaches,
    from: &str,
    mail_from_domain: &str,
) -> DmarcOutputHelper {
    let message = format!("From: {from}\r\n\r\n");
    let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
    let spf = SpfOutput {
        result: SpfResult::Pass,
        domain: mail_from_domain.to_string(),
        report: None,
        explanation: None,
        identity: None,
    };
    resolver
        .verify_dmarc(caches.parameters(DmarcParameters::new(
            &auth_message,
            &[],
            mail_from_domain,
            &spf,
        )))
        .await
}

async fn policy_of(resolver: &MessageAuthenticator, caches: &DummyCaches, from: &str) -> Policy {
    verify(resolver, caches, from).await.policy()
}

type DmarcOutputHelper = crate::DmarcOutput;

#[tokio::test]
async fn dmarc_verify_dkim2() {
    use crate::Dkim2Result;
    use crate::dkim2::{ChainLink, Dkim2Output, Signature as Dkim2Signature};

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();

    for (dmarc_dns, dmarc, message, signature_domain, dkim2_result, expect_dkim, policy) in [
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "example.org",
            Dkim2Result::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=r; adkim=r; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            Dkim2Result::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            Dkim2Result::Pass,
            DmarcResult::Fail(Error::NotAligned),
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "example.org",
            Dkim2Result::Fail(Error::NotAligned),
            DmarcResult::None,
            Policy::Reject,
        ),
    ] {
        caches.txt_add(
            dmarc_dns,
            DmarcRecord::parse(dmarc.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3200, 0),
        );

        let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
        let signature = Dkim2Signature {
            i: 1,
            d: signature_domain.into(),
            ..Default::default()
        };
        let dkim2 = Dkim2Output {
            chain: vec![ChainLink {
                signature: &signature,
                instance: None,
                result: dkim2_result.clone(),
                custody_ok: true,
            }],
            ..Dkim2Output::from(dkim2_result.clone())
        };
        let provisional = Dkim2Output {
            verification: crate::dkim2::Verification::Provisional,
            ..dkim2.clone()
        };
        let spf = SpfOutput {
            result: SpfResult::None,
            domain: "example.org".to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        let result = resolver
            .verify_dmarc(
                caches.parameters(
                    DmarcParameters::new(&auth_message, &[], "example.org", &spf)
                        .with_dkim2_output(&dkim2),
                ),
            )
            .await;
        assert_eq!(result.dkim_result, expect_dkim);
        assert_eq!(result.policy, policy);

        let result = resolver
            .verify_dmarc(
                caches.parameters(
                    DmarcParameters::new(&auth_message, &[], "example.org", &spf)
                        .with_dkim2_output(&provisional),
                ),
            )
            .await;
        assert!(
            !matches!(result.dkim_result, DmarcResult::Pass),
            "a provisional DKIM2 pass must not align"
        );
    }
}

#[tokio::test]
async fn dmarc_verify_report_address() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new().with_txt(
        "example.org._report._dmarc.external.org.",
        DmarcRecord::parse(b"v=DMARC1").unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );
    let uris = vec![
        Uri::new("dmarc@example.org", 0),
        Uri::new("dmarc@external.org", 0),
        Uri::new("domain@other.org", 0),
    ];

    assert_eq!(
        resolver
            .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
            .await
            .unwrap(),
        vec![
            &Uri::new("dmarc@example.org", 0),
            &Uri::new("dmarc@external.org", 0),
        ]
    );
}

#[tokio::test]
async fn dmarc_verify_report_address_idn() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    let uris = vec![
        Uri::new(
            "dmarc@\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            0,
        ),
        Uri::new("dmarc@sub.xn--eebajf.xn--9dbq2a", 0),
    ];

    assert_eq!(
        resolver
            .authorized_report_addresses(
                caches.parameters(("xn--eebajf.xn--9dbq2a", uris.as_slice()))
            )
            .await
            .unwrap(),
        uris.iter().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn dmarc_alignment_is_case_insensitive() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; aspf=s; rua=mailto:d@example.org").unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );

    let result = verify_aligned(&resolver, &caches, "hello@example.org", "EXAMPLE.ORG").await;
    assert_eq!(result.spf_result(), &DmarcResult::Pass);
}

// A TXT cache for the transaction tests. It holds records that stand in for
// cached DNS answers, records every write the discovery layer commits, and
// can hide chosen entries so the lookup falls through to the mock resolver
// (which answers names containing `_dns_error.` with a transient failure).
#[derive(Default)]
struct TransactionCache {
    records: std::sync::Mutex<std::collections::HashMap<Box<str>, TxtRecord>>,
    hidden: std::sync::Mutex<std::collections::HashSet<Box<str>>>,
    inserts: std::sync::Mutex<Vec<Box<str>>>,
}

impl TransactionCache {
    fn new() -> Self {
        Self::default()
    }

    fn seed(&self, name: &str, record: &str) {
        self.records.lock().unwrap().insert(
            name.into(),
            DmarcRecord::parse(record.as_bytes()).unwrap().into(),
        );
    }

    fn replace(&self, name: &str, record: &str) {
        self.seed(name, record);
    }

    fn hide(&self, name: &str) {
        self.hidden.lock().unwrap().insert(name.into());
    }

    fn show_all(&self) {
        self.hidden.lock().unwrap().clear();
    }

    fn committed(&self) -> Vec<Box<str>> {
        self.inserts.lock().unwrap().clone()
    }

    fn contains(&self, name: &str) -> bool {
        self.records.lock().unwrap().contains_key(name)
    }
}

impl ResolverCache<Box<str>, TxtRecord> for TransactionCache {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let records = self.records.lock().unwrap();
        let hidden = self.hidden.lock().unwrap();
        records.iter().find_map(|(key, value)| {
            let key_as_q: &Q = key.borrow();
            (key_as_q == name && !hidden.contains::<str>(key.as_ref()))
                .then(|| value.clone())
        })
    }

    fn remove<Q>(&self, _name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, key: Box<str>, value: TxtRecord, _valid_until: Instant) {
        self.records.lock().unwrap().insert(key.clone(), value);
        self.inserts.lock().unwrap().push(key);
    }
}

// A transient failure halfway through a tree walk must not publish any of
// the ancestor answers consulted before the failure: the whole discovery
// transaction is discarded, so a retry starts from a clean shared cache.
#[tokio::test]
async fn dmarc_walk_transient_error_discards_the_transaction() {
    use super::DmarcDiscovery;

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let cache = TransactionCache::new();

    // The two deepest names resolve from the cache; the next ancestor is a
    // `_dns_error.` name the mock resolver fails transiently. It is cached
    // at first but hidden, so the walk reaches the failing query.
    cache.seed(
        "_dmarc.b.mail._dns_error.example.com.",
        "v=DMARC1; p=none; sp=none; rua=mailto:d@example.com",
    );
    cache.seed(
        "_dmarc.mail._dns_error.example.com.",
        "v=DMARC1; p=none; sp=none; rua=mailto:d@example.com",
    );
    cache.hide("_dmarc.mail._dns_error.example.com.");

    let mut discovery = DmarcDiscovery::new(Some(&cache));
    let err = resolver
        .dmarc_tree_walk("a.b.mail._dns_error.example.com", &mut discovery)
        .await
        .expect_err("the walk must surface the transient resolver error");
    assert!(matches!(err, Error::Dns(DnsError::Resolver(_))));

    // Nothing from the aborted transaction was committed to the shared
    // cache: it still holds only the two records seeded before the walk,
    // and no negative/positive entry was written for the names the walk
    // consulted, which only lived in the discarded transaction snapshot.
    assert_eq!(cache.committed(), Vec::<Box<str>>::new());
    assert!(!cache.contains("_dmarc.a.b.mail._dns_error.example.com."));

    // Once the transient condition clears, the retry completes as one
    // coherent transaction, stopping at the psd=n record.
    cache.show_all();
    cache.seed(
        "_dmarc._dns_error.example.com.",
        "v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com",
    );
    let mut discovery = DmarcDiscovery::new(Some(&cache));
    let walk = resolver
        .dmarc_tree_walk("a.b.mail._dns_error.example.com", &mut discovery)
        .await
        .expect("the retry must complete");
    let names: Vec<&str> = walk.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        vec![
            "b.mail._dns_error.example.com",
            "mail._dns_error.example.com",
            "_dns_error.example.com"
        ]
    );
    assert_eq!(walk.last().unwrap().1.p, Policy::Reject);
}

// When a retry observes a changed PSD stop point, the walk must be built
// entirely from answers of one discovery transaction. Records of an older,
// differently-shaped walk can never be stitched together with new records
// into a mixed policy tree.
#[tokio::test]
async fn dmarc_walk_retry_never_mixes_two_policy_trees() {
    use super::DmarcDiscovery;

    let resolver = MessageAuthenticator::new_system_conf().unwrap();

    // Old DNS layout: the PSD stop point sits at bank.example.
    let old = TransactionCache::new();
    old.seed(
        "_dmarc.bank.example.",
        "v=DMARC1; p=reject; psd=y; rua=mailto:d@bank.example",
    );
    old.seed(
        "_dmarc.giant.bank.example.",
        "v=DMARC1; p=reject; rua=mailto:d@giant.bank.example",
    );
    let mut discovery = DmarcDiscovery::new(Some(&old));
    let walk = resolver
        .dmarc_tree_walk("mega.giant.bank.example", &mut discovery)
        .await
        .unwrap();
    assert_eq!(
        walk.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        vec!["giant.bank.example", "bank.example"]
    );

    // New DNS layout: the PSD stop point moved one label up to example,
    // bank.example lost psd=y, and every policy changed to none.
    let new = TransactionCache::new();
    new.seed(
        "_dmarc.example.",
        "v=DMARC1; p=none; psd=y; rua=mailto:d@example",
    );
    new.replace(
        "_dmarc.bank.example.",
        "v=DMARC1; p=none; rua=mailto:d@bank.example",
    );
    new.seed(
        "_dmarc.giant.bank.example.",
        "v=DMARC1; p=none; rua=mailto:d@giant.bank.example",
    );
    let mut discovery = DmarcDiscovery::new(Some(&new));
    let walk = resolver
        .dmarc_tree_walk("mega.giant.bank.example", &mut discovery)
        .await
        .unwrap();
    assert_eq!(
        walk.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        vec!["giant.bank.example", "bank.example", "example."]
    );
    // The whole new chain carries the new policy; no reject (old tree)
    // record survived into the new discovery.
    assert!(walk.iter().all(|(_, record)| record.p == Policy::None));
}

// A successful transaction keeps the legal no-record semantics (a missing
// DMARC record contributes no policy entry and is cached as a negative), and
// leaves psd, sp/np, rua and IDN (A-label) handling untouched.
#[tokio::test]
async fn dmarc_walk_transaction_preserves_record_semantics() {
    use super::DmarcDiscovery;

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let cache = TransactionCache::new();
    cache.seed(
        "_dmarc.xn--eebajf.xn--9dbq2a.",
        "v=DMARC1; p=quarantine; sp=reject; np=none; rua=mailto:d@xn--eebajf.xn--9dbq2a",
    );
    let mut discovery = DmarcDiscovery::new(Some(&cache));
    let walk = resolver
        .dmarc_tree_walk("sub.xn--eebajf.xn--9dbq2a", &mut discovery)
        .await
        .unwrap();
    assert_eq!(
        walk.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        vec!["xn--eebajf.xn--9dbq2a"]
    );
    let record = &walk[0].1;
    assert_eq!(record.p, Policy::Quarantine);
    assert_eq!(record.sp, Policy::Reject);
    assert_eq!(record.np, Policy::None);
    assert_eq!(record.rua.len(), 1);
    // The ancestor without a DMARC record got a cached negative answer.
    assert!(cache.contains("_dmarc.sub.xn--eebajf.xn--9dbq2a."));
}
