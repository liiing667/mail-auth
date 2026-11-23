/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcError, ChainLink, ChainValidation};
use crate::dns::{
    DnsCache, ResolverCache, ToFqdn, TxtRecord, TxtRecordParser, UnwrapTxtRecord,
};
use crate::{Instant, SystemTime};
use crate::{
    ArcOutput, AuthenticatedMessage, DkimResult, Error, MessageAuthenticator, Parameters,
    crypto::HashAlgorithm,
    dkim::{Canonicalization, verify::Verifier},
    dkim::{DomainKey, VerifySignature},
    headers::Header,
};
use std::sync::{Arc, Mutex};

impl MessageAuthenticator {
    /// Validates the ARC chain of a message (RFC 8617, Section 5.2).
    ///
    /// Takes a parsed [`AuthenticatedMessage`], optionally wrapped in
    /// [`Parameters`] to supply a DNS cache. The chain is checked for
    /// structure (instance numbers, `cv=` values, matching header counts),
    /// then the newest `ARC-Message-Signature` (body hash, expiration and
    /// signature) and every `ARC-Seal`, newest first, are verified. One DNS
    /// TXT lookup of the key at `<s>._domainkey.<d>` is performed for the
    /// newest `ARC-Message-Signature` and for each `ARC-Seal`.
    ///
    /// All key lookups of one call are bound to a single generation of the
    /// DNS cache: the generation reported by [`ResolverCache::generation`]
    /// is frozen when validation starts, records fetched from DNS are staged
    /// and published to the shared cache only when the call ends, and a
    /// cache whose generation changed meanwhile is bypassed rather than
    /// mixed into the chain. Every hop is therefore validated against one
    /// consistent view of the DNS keys, and a retried chain cannot combine
    /// headers, keys or seals of two cache generations.
    ///
    /// The [`ArcResult`](crate::ArcResult) of the returned [`ArcOutput`] is:
    ///
    /// - `None`: the message has no `ARC-Message-Signature` header; other ARC
    ///   headers are not examined in that case.
    /// - `Pass`: the chain validated.
    /// - `Fail`: the chain is broken (more than 50 sets, differing header
    ///   counts, wrong instance sequence, invalid `cv=`), or a signature or
    ///   seal failed cryptographic verification.
    /// - `Neutral`: an ARC header could not be parsed, or the newest
    ///   `ARC-Message-Signature` has expired or its body hash does not match.
    /// - `PermError`: a key record is missing or invalid.
    /// - `TempError`: a key lookup failed with a transient DNS error.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{AuthenticatedMessage, ArcResult, MessageAuthenticator};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator, raw_message: &[u8]) {
    /// let message = AuthenticatedMessage::parse(raw_message).unwrap();
    /// let output = authenticator.verify_arc(&message).await;
    /// match output.result() {
    ///     ArcResult::Pass => println!("chain of {} sets validated", output.chain().len()),
    ///     ArcResult::None => println!("no ARC chain"),
    ///     other => println!("arc={other}"),
    /// }
    /// # }
    /// ```
    pub async fn verify_arc<'x, C>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, C>>,
    ) -> ArcOutput<'x>
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        let txt_cache = params.txt_cache();
        let generation = txt_cache.map_or(0, |cache| cache.generation());
        let staged = Mutex::new(Vec::new());
        let cache = ChainCache::new(txt_cache, generation, &staged);
        let output = self.verify_arc_chain(params.input, &cache).await;
        cache.commit();
        output
    }

    async fn verify_arc_chain<'x, C>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        cache: &ChainCache<'_, C>,
    ) -> ArcOutput<'x>
    where
        C: ResolverCache<Box<str>, TxtRecord>,
    {
        if message.has_arc_errors {
            let err = message
                .errors
                .iter()
                .find_map(|h| match &h.header {
                    Error::Arc(_) => Some(h.header.clone()),
                    _ => None,
                })
                .unwrap_or(Error::Arc(ArcError::BrokenChain));
            return ArcOutput::default().with_result(DkimResult::Neutral(err));
        }
        let arc_headers = message.ams_headers.len();
        if arc_headers == 0 {
            return ArcOutput::default();
        } else if arc_headers > 50 {
            return ArcOutput::default()
                .with_result(DkimResult::Fail(Error::Arc(ArcError::ChainTooLong)));
        } else if (arc_headers != message.as_headers.len())
            || (arc_headers != message.aar_headers.len())
        {
            return ArcOutput::default()
                .with_result(DkimResult::Fail(Error::Arc(ArcError::BrokenChain)));
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut output = ArcOutput {
            result: DkimResult::None,
            set: Vec::with_capacity(message.aar_headers.len() / 3),
        };

        for (pos, ((seal_, signature_), results_)) in message
            .as_headers
            .iter()
            .zip(message.ams_headers.iter())
            .zip(message.aar_headers.iter())
            .enumerate()
        {
            let seal = &seal_.header;
            let signature = &signature_.header;
            let results = &results_.header;

            if output.result == DkimResult::None {
                if (seal.i as usize != (pos + 1))
                    || (signature.i as usize != (pos + 1))
                    || (results.i as usize != (pos + 1))
                {
                    output.result =
                        DkimResult::Fail(Error::Arc(ArcError::InvalidInstance((pos + 1) as u32)));
                } else if (pos == 0 && seal.cv != ChainValidation::None)
                    || (pos > 0 && seal.cv != ChainValidation::Pass)
                {
                    output.result = DkimResult::Fail(Error::Arc(ArcError::InvalidChainValidation));
                } else if pos == arc_headers - 1 {
                    if signature.x == 0 || (signature.x > signature.t && signature.x > now) {
                        let ha = HashAlgorithm::from(signature.a);
                        let bh = &message
                            .body_hashes
                            .iter()
                            .find(|(c, h, l, _)| {
                                c == &signature.cb && h == &ha && l == &signature.l
                            })
                            .unwrap()
                            .3;
                        if bh != &signature.bh {
                            output.result =
                                DkimResult::Neutral(Error::Arc(ArcError::BodyHashMismatch));
                        }
                    } else {
                        output.result = DkimResult::Neutral(Error::Arc(ArcError::SignatureExpired));
                    }
                }
            }

            output.set.push(ChainLink {
                signature: Header::new(signature_.name, signature_.value, signature),
                seal: Header::new(seal_.name, seal_.value, seal),
                results: Header::new(results_.name, results_.value, results),
            });
        }

        if output.result != DkimResult::None {
            return output;
        }

        let arc_set = output.set.last().unwrap();
        let header = &arc_set.signature;
        let signature = &header.header;

        let dkim_hdr_value = header.value.strip_signature();
        let mut headers = message.signed_headers(&signature.h, header.name, &dkim_hdr_value);

        let record = match self
            .arc_txt_lookup::<DomainKey, C>(signature.domain_key(), cache)
            .await
        {
            Ok(record) => record,
            Err(err) => {
                return output.with_result(err.into());
            }
        };

        if let Err(err) = record.verify(&mut headers, *signature, signature.ch) {
            return output.with_result(DkimResult::Fail(err));
        }

        for (pos, set) in output.set.iter().enumerate().rev() {
            let header = &set.seal;
            let seal = &header.header;
            let record = match self
                .arc_txt_lookup::<DomainKey, C>(seal.domain_key(), cache)
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    return output.with_result(err.into());
                }
            };

            let seal_signature = header.value.strip_signature();
            let mut headers = output
                .set
                .iter()
                .take(pos)
                .flat_map(|set| {
                    [
                        (set.results.name, set.results.value),
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                    ]
                })
                .chain([
                    (set.results.name, set.results.value),
                    (set.signature.name, set.signature.value),
                    (set.seal.name, &seal_signature),
                ]);

            if let Err(err) = record.verify(&mut headers, *seal, Canonicalization::Relaxed) {
                return output.with_result(DkimResult::Fail(err));
            }
        }

        output.with_result(DkimResult::Pass)
    }

    async fn arc_txt_lookup<T, C>(
        &self,
        key: impl ToFqdn,
        cache: &ChainCache<'_, C>,
    ) -> crate::Result<Arc<T>>
    where
        T: TxtRecordParser + Into<TxtRecord> + UnwrapTxtRecord,
        C: ResolverCache<Box<str>, TxtRecord>,
    {
        if cache.shared.is_none() {
            self.txt_lookup::<T>(key, None::<&C>).await
        } else {
            self.txt_lookup::<T>(key, Some(cache)).await
        }
    }
}

/// A per-chain view of the shared TXT cache.
///
/// Reads only see entries that were already in the shared cache with the
/// same generation. Writes are staged with the chain's generation and
/// published once the whole chain has been evaluated. A key fetched for one
/// hop therefore cannot leak into another chain evaluation, while a cache
/// populated before the call is still shared by all hops as usual.
struct ChainCache<'a, C> {
    shared: Option<&'a C>,
    generation: u64,
    staged: &'a Mutex<Vec<(u64, Box<str>, TxtRecord, Instant)>>,
}

impl<'a, C> ChainCache<'a, C>
where
    C: ResolverCache<Box<str>, TxtRecord>,
{
    fn new(
        shared: Option<&'a C>,
        generation: u64,
        staged: &'a Mutex<Vec<(u64, Box<str>, TxtRecord, Instant)>>,
    ) -> Self {
        ChainCache {
            shared,
            generation,
            staged,
        }
    }

    fn commit(&self) {
        let staged = {
            let mut staged = self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *staged)
        };
        if let Some(shared) = self.shared {
            let current = shared.generation();
            let mut published: Vec<Box<str>> = Vec::new();
            for (generation, key, value, valid_until) in staged.into_iter().rev() {
                if current != 0 && generation != current {
                    // This answer belongs to a cache generation that has
                    // since been replaced.
                    continue;
                }
                if published.iter().any(|seen| seen == &key) {
                    continue;
                }
                // On a generation-tracking cache the staged answer belongs to
                // the current generation and replaces any stale entry. When
                // the cache does not track generations, do not overwrite a
                // value that another writer may have refreshed meanwhile.
                if current != 0 || shared.get::<str>(&key).is_none() {
                    published.push(key.clone());
                    shared.insert(key, value, valid_until);
                }
            }
        }
    }
}

impl<C> ResolverCache<Box<str>, TxtRecord> for ChainCache<'_, C>
where
    C: ResolverCache<Box<str>, TxtRecord>,
{
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let shared = self.shared?;
        let current = shared.generation();
        if current != 0 && current != self.generation {
            return None;
        }
        shared.get(name)
    }

    fn remove<Q>(&self, key: &Q) -> Option<TxtRecord>
    where
        Box<str>: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let shared = self.shared?;
        let current = shared.generation();
        if current == 0 || current == self.generation {
            shared.remove(key)
        } else {
            None
        }
    }

    fn insert(&self, key: Box<str>, value: TxtRecord, valid_until: Instant) {
        self.staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((self.generation, key, value, valid_until));
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use mail_parser::MessageParser;

    use crate::{
        AuthenticatedMessage, AuthenticationResults, DkimResult, DnsError, Error,
        MessageAuthenticator, Parameters,
        arc::ArcSealer,
        crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
        dkim::{DkimSigner, DomainKey},
        dkim::verify::test::new_cache,
        dns::cache::test::{DummyCache, DummyCaches},
        dns::{DnsCache, Mx, Negative, RecordSet, ResolverCache, TxtRecord},
        headers::HeaderWriter,
        parse::TxtRecordParser,
    };
    use encodify::base64;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, pem::PemObject};
    use std::{
        borrow::Borrow,
        hash::Hash,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    const RSA_PRIVATE_KEY: &str = include_str!("../../resources/rsa-private.pem");

    const RSA_PUBLIC_KEY: &str = concat!(
        "v=DKIM1; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ",
        "8AMIIBCgKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm",
        "1agrbcnSk5oIaEfMZLUR/X8gPzoiNHZcfMZEVR6bAytxUh",
        "c5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIaUmSACj0dL2/K",
        "wW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bW",
        "PZNkT4NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0",
        "TqgXdtw6A4Sdsp97VXT9fkPW9rso3lrkpsl/9EQ1mR/DWK",
        "6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Aed4l9",
        "WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQAB",
    );

    const ED25519_PRIVATE_KEY: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const ED25519_PUBLIC_KEY: &str =
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    const TEST_MESSAGE: &str = concat!(
        "From: queso@manchego.org\r\n",
        "To: affumicata@scamorza.org\r\n",
        "Subject: Say cheese\r\n",
        "\r\n",
        "We need to settle which one of us ",
        "is tastier.\r\n"
    );

    #[tokio::test]
    async fn arc_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arc");
        let resolver = MessageAuthenticator::new_system_conf().unwrap();

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            println!("file {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, raw_message) = test.split_once("\n\n").unwrap();
            let caches = new_cache(dns_records);
            let raw_message = raw_message.replace('\n', "\r\n");
            let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
            assert_eq!(
                message,
                AuthenticatedMessage::from_parsed(
                    &MessageParser::new().parse(&raw_message).unwrap(),
                    raw_message.as_bytes(),
                    true
                )
            );

            let arc = resolver.verify_arc(caches.parameters(&message)).await;
            assert_eq!(arc.result(), &DkimResult::Pass);

            let dkim = resolver.verify_dkim(caches.parameters(&message)).await;
            assert!(dkim.iter().any(|o| o.result() == &DkimResult::Pass));
        }
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::new(3600, 0)
    }

    fn rsa_key() -> RsaKey<Sha256> {
        RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap()
    }

    fn ed25519_key() -> Ed25519Key {
        let public = base64::LENIENT
            .decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1)
            .unwrap();
        let private = base64::LENIENT.decode(ED25519_PRIVATE_KEY).unwrap();
        Ed25519Key::from_seed_and_public_key(&private, &public).unwrap()
    }

    fn test_caches() -> DummyCaches {
        DummyCaches::new()
            .with_txt(
                "rsa._domainkey.manchego.org.".to_string(),
                DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
                far_future(),
            )
            .with_txt(
                "ed._domainkey.scamorza.org.".to_string(),
                DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
                far_future(),
            )
            .with_txt(
                "ed_dns_error._domainkey.scamorza.org.".to_string(),
                DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
                far_future(),
            )
    }

    async fn arc_seal_message(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        raw_message: &str,
        d: &str,
        s: &str,
        pk: impl SigningKey<Hasher = Sha256>,
    ) -> String {
        let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
        let dkim_result = resolver.verify_dkim(caches.parameters(&message)).await;
        let arc_result = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(arc_result.result(), DkimResult::Pass | DkimResult::None),
            "ARC validation failed while sealing: {:?}",
            arc_result.result()
        );
        let auth_results = AuthenticationResults::new(d).with_dkim_results(&dkim_result, d);
        let arc = ArcSealer::from_key(pk)
            .domain(d)
            .selector(s)
            .headers(["From", "To", "Subject", "DKIM-Signature"])
            .seal(&message, &auth_results, &arc_result)
            .unwrap_or_else(|err| panic!("Got {err:?} for {raw_message}"));
        format!(
            "{}{}{}",
            arc.to_header(),
            auth_results.to_header(),
            raw_message
        )
    }

    /// Builds a three-hop chain (manchego.org, scamorza.org, manchego.org)
    /// with `hop2_selector` as the middle hop's selector.
    async fn build_three_hop_chain(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        hop2_selector: &str,
    ) -> String {
        let mut raw_message = DkimSigner::from_key(rsa_key())
            .domain("manchego.org")
            .selector("rsa")
            .headers(["From", "To", "Subject"])
            .sign(TEST_MESSAGE.as_bytes())
            .unwrap()
            .to_header()
            + TEST_MESSAGE;
        raw_message = arc_seal_message(
            resolver,
            caches,
            &raw_message,
            "manchego.org",
            "rsa",
            rsa_key(),
        )
        .await;
        raw_message = arc_seal_message(
            resolver,
            caches,
            &raw_message,
            "scamorza.org",
            hop2_selector,
            ed25519_key(),
        )
        .await;
        arc_seal_message(
            resolver,
            caches,
            &raw_message,
            "manchego.org",
            "rsa",
            rsa_key(),
        )
        .await
    }

    /// Splits the first header field (including folded lines) from the rest
    /// of the message.
    fn split_first_header(raw: &str) -> (&str, &str) {
        let mut pos = 0;
        loop {
            let end = raw[pos..].find("\r\n").map(|i| pos + i).unwrap();
            let next = end + 2;
            if next >= raw.len() || !matches!(raw.as_bytes()[next], b' ' | b'\t') {
                return (&raw[..next], &raw[next..]);
            }
            pos = next;
        }
    }

    #[tokio::test]
    async fn arc_verify_retry_with_new_selector() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();

        // Two three-hop chains that differ only in the middle hop's
        // selector: `ed_dns_error` simulates a key whose lookup fails
        // temporarily, `ed` is the selector used after the retry.
        let chain_a = build_three_hop_chain(&resolver, &test_caches(), "ed_dns_error").await;
        let chain_b = build_three_hop_chain(&resolver, &test_caches(), "ed").await;

        // Both chains validate against a healthy DNS view.
        for chain in [&chain_a, &chain_b] {
            let message = AuthenticatedMessage::parse(chain.as_bytes()).unwrap();
            let caches = test_caches();
            let output = resolver.verify_arc(caches.parameters(&message)).await;
            assert_eq!(output.result(), &DkimResult::Pass);
            assert_eq!(output.chain().len(), 3);
        }

        // The middle hop key of chain A fails temporarily: the TempError is
        // preserved and nothing is cached for the failed name.
        let caches = DummyCaches::new().with_txt(
            "rsa._domainkey.manchego.org.".to_string(),
            DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
            far_future(),
        );
        let message = AuthenticatedMessage::parse(chain_a.as_bytes()).unwrap();
        let output = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(output.result(), DkimResult::TempError(_)),
            "expected TempError, got {:?}",
            output.result()
        );
        assert!(
            caches
                .txt
                .get::<str>("ed_dns_error._domainkey.scamorza.org.")
                .is_none(),
            "a temporary failure must not be cached"
        );

        // The retried chain (new middle selector) validates, but the final
        // seal of the old chain cannot be grafted onto it: the seal is bound
        // to the headers of its own chain generation.
        let (seal_a, _) = split_first_header(&chain_a);
        let (seal_b, rest_b) = split_first_header(&chain_b);
        assert!(seal_a.starts_with("ARC-Seal: i=3;"));
        assert!(seal_b.starts_with("ARC-Seal: i=3;"));
        assert_ne!(seal_a, seal_b);
        let grafted = format!("{seal_a}{rest_b}");
        let message = AuthenticatedMessage::parse(grafted.as_bytes()).unwrap();
        let caches = test_caches();
        let output = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(output.result(), DkimResult::Fail(_)),
            "expected Fail for a grafted seal, got {:?}",
            output.result()
        );
    }

    #[tokio::test]
    async fn arc_verify_unclaimed_chain_caches_negative() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let chain_b = build_three_hop_chain(&resolver, &test_caches(), "ed").await;

        // The middle hop key is not claimed by the cache: the lookup goes to
        // DNS, the negative answer is reported as PermError and published
        // when the call ends.
        let caches = DummyCaches::new().with_txt(
            "rsa._domainkey.manchego.org.".to_string(),
            DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
            far_future(),
        );
        let message = AuthenticatedMessage::parse(chain_b.as_bytes()).unwrap();
        let output = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(
                output.result(),
                DkimResult::PermError(Error::Dns(DnsError::RecordNotFound(_)))
            ),
            "expected PermError, got {:?}",
            output.result()
        );
        assert!(matches!(
            caches.txt.get::<str>("ed._domainkey.scamorza.org."),
            Some(TxtRecord::Error(_))
        ));

        // A retry observes the same answer, now from the cache.
        let output = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(
                output.result(),
                DkimResult::PermError(Error::Dns(DnsError::RecordNotFound(_)))
            ),
            "expected cached PermError, got {:?}",
            output.result()
        );
    }

    /// A TXT cache that replaces one entry (simulating a key rotation by
    /// another writer) after `rotate_at` reads.
    struct RotatingTxtCache {
        inner: DummyCache<Box<str>, TxtRecord>,
        gets: AtomicUsize,
        rotate_at: usize,
        rotate_key: Box<str>,
        rotate_value: TxtRecord,
    }

    impl ResolverCache<Box<str>, TxtRecord> for RotatingTxtCache {
        fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
        where
            Box<str>: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            let value = self.inner.get(name);
            if self.gets.fetch_add(1, Ordering::Relaxed) + 1 == self.rotate_at {
                self.inner
                    .insert(self.rotate_key.clone(), self.rotate_value.clone(), far_future());
            }
            value
        }

        fn remove<Q>(&self, name: &Q) -> Option<TxtRecord>
        where
            Box<str>: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.inner.remove(name)
        }

        fn insert(&self, key: Box<str>, value: TxtRecord, valid_until: Instant) {
            self.inner.insert(key, value, valid_until);
        }

        fn generation(&self) -> u64 {
            self.inner.generation()
        }
    }

    struct RotatingCaches {
        txt: RotatingTxtCache,
        others: DummyCaches,
    }

    impl DnsCache for RotatingCaches {
        type Txt = RotatingTxtCache;
        type Mx = DummyCache<Box<str>, Result<RecordSet<Mx>, Negative>>;
        type Ipv4 = DummyCache<Box<str>, Result<RecordSet<Ipv4Addr>, Negative>>;
        type Ipv6 = DummyCache<Box<str>, Result<RecordSet<Ipv6Addr>, Negative>>;
        type Ptr = DummyCache<IpAddr, Result<RecordSet<Box<str>>, Negative>>;

        fn txt(&self) -> Option<&Self::Txt> {
            Some(&self.txt)
        }

        fn mx(&self) -> Option<&Self::Mx> {
            Some(&self.others.mx)
        }

        fn ipv4(&self) -> Option<&Self::Ipv4> {
            Some(&self.others.ipv4)
        }

        fn ipv6(&self) -> Option<&Self::Ipv6> {
            Some(&self.others.ipv6)
        }

        fn ptr(&self) -> Option<&Self::Ptr> {
            Some(&self.others.ptr)
        }
    }

    #[tokio::test]
    async fn arc_verify_cache_generation_rotation() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let chain_b = build_three_hop_chain(&resolver, &test_caches(), "ed").await;

        // The key of the first and last hop is rotated by another writer
        // while the chain is being validated.
        let caches = RotatingCaches {
            txt: RotatingTxtCache {
                inner: DummyCache::new(),
                gets: AtomicUsize::new(0),
                rotate_at: 3,
                rotate_key: "rsa._domainkey.manchego.org.".into(),
                rotate_value: DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes())
                    .unwrap()
                    .into(),
            },
            others: DummyCaches::new(),
        };
        caches.txt.inner.insert(
            "rsa._domainkey.manchego.org.".into(),
            DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap().into(),
            far_future(),
        );
        caches.txt.inner.insert(
            "ed._domainkey.scamorza.org.".into(),
            DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap().into(),
            far_future(),
        );

        let message = AuthenticatedMessage::parse(chain_b.as_bytes()).unwrap();

        // The validation cannot mix two cache generations: the last hop does
        // not see the rotated key, its lookup goes to DNS and the staged
        // negative answer is not published over the rotated entry.
        let output = resolver
            .verify_arc(Parameters::new(&message).with_cache(&caches))
            .await;
        assert!(
            matches!(
                output.result(),
                DkimResult::PermError(Error::Dns(DnsError::RecordNotFound(_)))
            ),
            "expected PermError, got {:?}",
            output.result()
        );
        assert!(
            matches!(
                caches
                    .txt
                    .inner
                    .get::<str>("rsa._domainkey.manchego.org."),
                Some(TxtRecord::DomainKey(_))
            ),
            "the rotated entry must not be replaced by a staged answer"
        );

        // A retry sees one consistent (rotated) generation and fails instead
        // of combining keys or seals of two generations.
        let output = resolver
            .verify_arc(Parameters::new(&message).with_cache(&caches))
            .await;
        assert!(
            matches!(output.result(), DkimResult::Fail(_)),
            "expected Fail, got {:?}",
            output.result()
        );
    }
}
