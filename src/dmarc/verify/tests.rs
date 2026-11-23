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

// A TXT cache for the authorization-transaction tests. It stands in for an
// application cache: it holds pre-seeded records, records every committed
// write and lets the mock resolver answer names containing `_dns_error.`
// with a transient failure.
#[derive(Default)]
struct ReportCache {
    records: std::sync::Mutex<std::collections::HashMap<Box<str>, TxtRecord>>,
    inserts: std::sync::Mutex<Vec<Box<str>>>,
}

impl ReportCache {
    fn new() -> Self {
        Self::default()
    }

    fn seed(&self, name: &str, record: &str) {
        self.records.lock().unwrap().insert(
            name.into(),
            DmarcRecord::parse(record.as_bytes()).unwrap().into(),
        );
    }

    fn committed(&self) -> Vec<Box<str>> {
        self.inserts.lock().unwrap().clone()
    }

    fn contains(&self, name: &str) -> bool {
        self.records.lock().unwrap().contains_key(name)
    }
}

impl ResolverCache<Box<str>, TxtRecord> for ReportCache {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let records = self.records.lock().unwrap();
        records.iter().find_map(|(key, value)| {
            let key_as_q: &Q = key.borrow();
            (key_as_q == name).then(|| value.clone())
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

struct ReportCaches {
    txt: ReportCache,
}

impl ReportCaches {
    fn new() -> Self {
        Self {
            txt: ReportCache::new(),
        }
    }

    fn parameters<'a, T>(&'a self, param: T) -> crate::dns::Parameters<'a, T, ReportCaches> {
        crate::dns::Parameters::new(param).with_cache(self)
    }
}

impl crate::dns::DnsCache for ReportCaches {
    type Txt = ReportCache;
    type Mx = crate::dns::cache::NoCache;
    type Ipv4 = crate::dns::cache::NoCache;
    type Ipv6 = crate::dns::cache::NoCache;
    type Ptr = crate::dns::cache::NoCache;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        None
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        None
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        None
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        None
    }
}

// Two external destinations must each be authorized against their own
// `<policy-domain>._report._dmarc.<destination-domain>` record. The second
// destination has no record and must not inherit the first one's
// authorization; the returned order matches the input order.
#[tokio::test]
async fn report_authorization_is_checked_per_address() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");
    let uris = vec![
        Uri::new("dmarc@example.org", 0),
        Uri::new("dmarc@external.org", 0),
        Uri::new("domain@other.org", 0),
        Uri::new("nested@mail.example.org", 0),
    ];

    let authorized = resolver
        .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
        .await
        .unwrap();
    assert_eq!(
        authorized,
        vec![
            &Uri::new("dmarc@example.org", 0),
            &Uri::new("dmarc@external.org", 0),
            &Uri::new("nested@mail.example.org", 0),
        ],
        "each address is authorized from its own source, in input order"
    );

    // The seeded external.org record is read from the shared cache, while the
    // missing record for other.org is looked up and cached as a negative
    // answer at commit.
    let committed = caches.txt.committed();
    assert!(committed
        .iter()
        .any(|key| key.as_ref() == "example.org._report._dmarc.other.org."));
    assert!(caches
        .txt
        .contains("example.org._report._dmarc.external.org."));
}

// An authorization answer is bound to its policy domain: the same
// destination domain authorized for one policy domain must not be treated as
// authorized for a different policy domain that never published a record.
#[tokio::test]
async fn report_authorization_does_not_cross_policy_domains() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");

    // First transaction: example.org is authorized to send to external.org.
    let uris_a = vec![Uri::new("dmarc@external.org", 0)];
    let authorized_a = resolver
        .authorized_report_addresses(caches.parameters(("example.org", uris_a.as_slice())))
        .await
        .unwrap();
    assert_eq!(authorized_a, vec![&Uri::new("dmarc@external.org", 0)]);

    // Second transaction for another policy domain: the cached record of the
    // first transaction has a different owner label and cannot be borrowed.
    let uris_b = vec![Uri::new("dmarc@external.org", 0)];
    let authorized_b = resolver
        .authorized_report_addresses(caches.parameters(("elsewhere.net", uris_b.as_slice())))
        .await
        .unwrap();
    assert!(
        authorized_b.is_empty(),
        "external.org is not authorized for elsewhere.net"
    );
    assert!(caches
        .txt
        .contains("elsewhere.net._report._dmarc.external.org."));
}

// A transient failure while checking one destination must discard the whole
// transaction: none of the answers consulted before the failure (including
// the first destination's successful authorization) reach the shared cache,
// so a retry cannot combine stale entries with freshly fetched ones.
#[tokio::test]
async fn report_authorization_temp_error_discards_the_transaction() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();

    // The first destination's record is a normal shared-cache hit, read
    // through the transaction's write gate; the second destination's name
    // contains `_dns_error.` and the mock resolver fails transiently.
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");
    let uris = vec![
        Uri::new("dmarc@external.org", 0),
        Uri::new("dmarc@flaky._dns_error.example.net", 0),
    ];

    let err = resolver
        .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Dns(DnsError::Resolver(_))),
        "expected a TempError, got {err:?}"
    );
    assert!(
        caches.txt.committed().is_empty(),
        "a failed transaction must not publish any answer"
    );
    assert!(
        !caches
            .txt
            .contains("example.org._report._dmarc.flaky._dns_error.example.net."),
        "the failing lookup leaves nothing in the shared cache"
    );

    // Retry with the failing destination replaced by an authorized one: the
    // retry re-evaluates every destination from the pre-transaction cache
    // state and commits one coherent set of answers.
    let retry_uris = vec![
        Uri::new("dmarc@external.org", 0),
        Uri::new("dmarc@backup.org", 0),
    ];
    caches.txt.seed("example.org._report._dmarc.backup.org.", "v=DMARC1");
    let authorized = resolver
        .authorized_report_addresses(caches.parameters(("example.org", retry_uris.as_slice())))
        .await
        .unwrap();
    assert_eq!(
        authorized,
        vec![
            &Uri::new("dmarc@external.org", 0),
            &Uri::new("dmarc@backup.org", 0),
        ],
        "the retry authorizes every destination from its own record"
    );
    let committed = caches.txt.committed();
    // Both records were already present in the shared cache, so the
    // successful retry needs no extra writes: a completed transaction never
    // overwrites an existing entry.
    assert!(committed.is_empty());
    assert!(caches
        .txt
        .contains("example.org._report._dmarc.external.org."));
    assert!(caches
        .txt
        .contains("example.org._report._dmarc.backup.org."));
}

// A retried call with the same addresses re-evaluates every destination from
// its own authorization name once the transient condition clears, and keeps
// the input order. No answer from the failed attempt survives in the cache.
#[tokio::test]
async fn report_authorization_retry_after_temp_error_starts_clean() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    // A seeded, visible answer for the first destination. The second one only
    // becomes reachable through the mock resolver once its transient-failure
    // name is replaced.
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");
    let failing_uris = vec![
        Uri::new("dmarc@external.org", 0),
        Uri::new("dmarc@down._dns_error.example.net", 0),
    ];
    assert!(resolver
        .authorized_report_addresses(caches.parameters(("example.org", failing_uris.as_slice())))
        .await
        .is_err());
    assert!(caches.txt.committed().is_empty());

    // Same first destination, second destination now backed by an
    // authorization record rather than a failing name.
    caches.txt.seed("example.org._report._dmarc.recovered.example.net.", "v=DMARC1");
    let retry_uris = vec![
        Uri::new("dmarc@external.org", 0),
        Uri::new("dmarc@recovered.example.net", 0),
    ];
    let authorized = resolver
        .authorized_report_addresses(caches.parameters(("example.org", retry_uris.as_slice())))
        .await
        .unwrap();
    assert_eq!(
        authorized,
        vec![
            &Uri::new("dmarc@external.org", 0),
            &Uri::new("dmarc@recovered.example.net", 0),
        ]
    );
    // The failed attempt left no stale entry behind.
    assert!(!caches
        .txt
        .contains("example.org._report._dmarc.down._dns_error.example.net."));
    assert!(caches
        .txt
        .contains("example.org._report._dmarc.recovered.example.net."));
}

// Duplicate destinations within one transaction consult the authorization
// record once and are both returned, in order, from the same staged answer.
#[tokio::test]
async fn report_authorization_dedupes_lookups_within_a_transaction() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    // No pre-seeded answer: the first lookup reaches the mock resolver,
    // stages its (negative) answer in the transaction and the second
    // identical destination reads the staged answer instead of querying
    // again. A negative name carries an SOA in the mock resolver, so it is
    // cacheable and published exactly once at commit.
    let uris = vec![
        Uri::new("a@external.org", 0),
        Uri::new("b@external.org", 0),
    ];

    let before = caches.txt.committed().len();
    let authorized = resolver
        .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
        .await
        .unwrap();
    assert!(authorized.is_empty(), "external.org is not authorized");
    assert_eq!(
        caches.txt.committed().len(),
        before + 1,
        "the duplicated destination produces one lookup and one cached answer"
    );
    assert_eq!(
        caches
            .txt
            .committed()
            .iter()
            .filter(|key| key.as_ref() == "example.org._report._dmarc.external.org.")
            .count(),
        1
    );
}

// IDN policy and destination domains are converted to A-labels before the
// authorization name is built, so Unicode and punycode spellings share one
// authorization source.
#[tokio::test]
async fn report_authorization_idn_uses_a_labels() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    // Use the same IDN policy domain as the alignment tests:
    // \u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd} is
    // xn--eebajf.xn--9dbq2a.
    caches.txt.seed("xn--eebajf.xn--9dbq2a._report._dmarc.xn--9dbd7b.xn--9dbq2a.", "v=DMARC1");
    // The destination domain is written once in Unicode
    // (\u{5d7}\u{5d5}\u{5e5}.\u{5e7}\u{5d5}\u{5dd}, punycode
    // xn--9dbd7b.xn--9dbq2a) and once as an A-label.
    let uris = vec![
        Uri::new(
            "dmarc@\u{5d7}\u{5d5}\u{5e5}.\u{5e7}\u{5d5}\u{5dd}",
            0,
        ),
        Uri::new("dmarc@xn--9dbd7b.xn--9dbq2a", 0),
    ];

    let authorized = resolver
        .authorized_report_addresses(caches.parameters((
            "\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            uris.as_slice(),
        )))
        .await
        .unwrap();
    assert_eq!(
        authorized,
        vec![
            &Uri::new(
                "dmarc@\u{5d7}\u{5d5}\u{5e5}.\u{5e7}\u{5d5}\u{5dd}",
                0
            ),
            &Uri::new("dmarc@xn--9dbd7b.xn--9dbq2a", 0),
        ]
    );

    // The punycode spelling and the Unicode spelling resolve to the same
    // authorization name, so both destinations are authorized from the single
    // pre-seeded record without any extra cache write.
    assert!(caches.txt.committed().is_empty());
    assert!(caches.txt.contains(
        "xn--eebajf.xn--9dbq2a._report._dmarc.xn--9dbd7b.xn--9dbq2a."
    ));
}

// The `rua` and `ruf` destination sets of one policy record are authorized
// independently: an external destination authorized for the aggregate
// (`rua`) transaction is not silently accepted as a failure-report (`ruf`)
// destination without its own authorization record.
#[tokio::test]
async fn report_authorization_rua_and_ruf_do_not_borrow_each_other() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    let record = DmarcRecord::parse(
        b"v=DMARC1; p=none; \
          rua=mailto:agg@external.org,mailto:agg@other.org; \
          ruf=mailto:forensic@external.org,mailto:forensic@unauthorized.org",
    )
    .unwrap();
    // Only external.org is authorized by the policy domain. other.org and
    // unauthorized.org have no `_report._dmarc` records.
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");

    let rua = resolver
        .authorized_report_addresses(caches.parameters(("example.org", record.rua())))
        .await
        .unwrap();
    assert_eq!(rua, vec![&Uri::new("agg@external.org", 0)]);

    let ruf = resolver
        .authorized_report_addresses(caches.parameters(("example.org", record.ruf())))
        .await
        .unwrap();
    assert_eq!(
        ruf,
        vec![&Uri::new("forensic@external.org", 0)],
        "ruf destinations need their own authorization records"
    );

    // Every external destination was queried under its own authorization
    // name, regardless of which tag (rua/ruf) it came from.
    assert!(caches
        .txt
        .contains("example.org._report._dmarc.external.org."));
    for destination in ["external.org", "other.org", "unauthorized.org"] {
        let name = format!("example.org._report._dmarc.{destination}.");
        assert!(caches.txt.contains(&name), "missing cached answer for {name}");
    }
    // The two destinations without records contributed negative answers.
    for destination in ["other.org", "unauthorized.org"] {
        let name = format!("example.org._report._dmarc.{destination}.");
        assert!(
            caches.txt.committed().iter().any(|key| key.as_ref() == name),
            "missing committed negative answer for {name}"
        );
    }
}

// A transaction that fails transiently publishes nothing, and a later
// transaction for a different policy domain cannot observe any of the
// discarded answers.
#[tokio::test]
async fn report_authorization_failed_tx_is_invisible_to_other_policy_domains() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = ReportCaches::new();
    caches.txt.seed("example.org._report._dmarc.external.org.", "v=DMARC1");

    let uris = vec![
        Uri::new("dmarc@external.org", 0),
        Uri::new("dmarc@down._dns_error.example.net", 0),
    ];
    assert!(resolver
        .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
        .await
        .is_err());
    assert!(caches.txt.committed().is_empty());

    // A different policy domain reusing the same destination must query its
    // own authorization name instead of borrowing the discarded answer.
    let other = vec![Uri::new("dmarc@external.org", 0)];
    let authorized = resolver
        .authorized_report_addresses(caches.parameters(("brand-new.example", other.as_slice())))
        .await
        .unwrap();
    assert!(authorized.is_empty());
    assert!(caches
        .txt
        .contains("brand-new.example._report._dmarc.external.org."));
    // The failed lookup of the first attempt left no entry behind.
    assert!(!caches
        .txt
        .contains("example.org._report._dmarc.down._dns_error.example.net."));
}
