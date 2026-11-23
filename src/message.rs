/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsed view of an RFC 5322 message for authentication.
//!
//! [`AuthenticatedMessage`] splits a raw message into headers and body,
//! parses the authentication headers it contains (`DKIM-Signature` from
//! RFC 6376, `ARC-Seal`, `ARC-Message-Signature` and
//! `ARC-Authentication-Results` from RFC 8617, `DKIM2-Signature` and
//! `Message-Instance` from draft-ietf-dkim-dkim2-spec) and precomputes the
//! body hashes the DKIM and ARC verifiers need. The verifiers on
//! [`MessageAuthenticator`](crate::MessageAuthenticator) take it as input.

#[cfg(feature = "arc")]
use crate::arc;
use crate::{
    Error,
    crypto::{HashAlgorithm, HashContext, HashImpl, Sha256},
    dkim::{self, Canonicalization},
    dkim2::{self, Dkim2Hash, canonicalize::Digests},
    headers::{AuthenticatedHeader, Header, HeaderParser, Writer},
};
use mail_parser::{AddressList, HeaderForm, HeaderName, Message};

const EXPECTED_HEADER_COUNT: usize = 32;

/// An opaque identity for one parsed message revision.
///
/// The identity covers the header snapshot, the body offset and every body
/// hash computed while parsing (or streamed into the message). Two parsed
/// revisions with the same evidence have the same identity; changing a
/// header, the body or the canonicalization evidence produces a different
/// identity.
///
/// Verification results carry this value so that a result produced for one
/// message snapshot cannot be presented as the result of another snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MessageIdentity {
    digest: [u8; 16],
    len: u64,
}

impl MessageIdentity {
    /// Returns the opaque digest that identifies the message revision.
    pub fn digest(&self) -> [u8; 16] {
        self.digest
    }

    /// Returns the length in bytes of the message revision.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` when the identity was produced for an empty message.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when this identity was produced for `message`.
    pub fn is_for_message(&self, message: &AuthenticatedMessage<'_>) -> bool {
        *self == message.identity()
    }

    pub(crate) fn new(digest: [u8; 16], len: u64) -> Self {
        MessageIdentity { digest, len }
    }
}

/// Deterministic hasher used to derive [`MessageIdentity`] values and the
/// per-signature identity attached to a [`DkimOutput`](crate::DkimOutput).
pub(crate) struct IdentityHasher {
    hasher: <Sha256 as HashImpl>::Context,
}

impl IdentityHasher {
    pub(crate) fn new() -> Self {
        IdentityHasher {
            hasher: Sha256::hasher(),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.hasher.write(bytes);
    }

    pub(crate) fn update_u64(&mut self, value: u64) {
        self.update(&value.to_be_bytes());
    }

    pub(crate) fn finish(self) -> [u8; 16] {
        let digest = self.hasher.complete();
        let mut identity = [0u8; 16];
        identity.copy_from_slice(&digest.as_ref()[..16]);
        identity
    }
}

/// An RFC 5322 message prepared for DKIM, DKIM2, ARC and DMARC verification.
///
/// The message borrows the raw bytes it was parsed from. Parsing records the
/// position of every header, the `From` addresses (used for DMARC, RFC 9989),
/// the number of `Received` headers and the presence of `Date` and
/// `Message-ID`. Authentication headers that fail to parse do not abort
/// parsing: they are recorded in [`errors`](Self::errors) and flagged by
/// [`has_dkim_errors`](Self::has_dkim_errors),
/// [`has_dkim2_errors`](Self::has_dkim2_errors) and `has_arc_errors`.
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::AuthenticatedMessage;
///
/// let raw = b"From: jdoe@example.org\r\nSubject: Hi\r\n\r\nHello\r\n";
/// let message = AuthenticatedMessage::parse(raw).unwrap();
/// assert_eq!(message.first_from_address(), "jdoe@example.org");
/// assert_eq!(message.raw_body(), b"Hello\r\n");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<String>,
    pub(crate) raw_message: &'x [u8],
    pub(crate) body_offset: u32,
    pub(crate) body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub(crate) streamed_body: Option<Box<StreamedBody>>,
    pub(crate) dkim_headers: Vec<Header<'x, dkim::Signature>>,
    pub(crate) dkim2_signatures: Vec<Header<'x, dkim2::Signature>>,
    pub(crate) dkim2_instances: Vec<Header<'x, dkim2::MessageInstance>>,
    #[cfg(feature = "arc")]
    pub(crate) ams_headers: Vec<Header<'x, arc::Signature>>,
    #[cfg(feature = "arc")]
    pub(crate) as_headers: Vec<Header<'x, arc::Seal>>,
    #[cfg(feature = "arc")]
    pub(crate) aar_headers: Vec<Header<'x, arc::ArcAuthResults>>,
    pub(crate) received_headers_count: usize,
    pub(crate) date_header_present: bool,
    pub(crate) message_id_header_present: bool,
    pub(crate) errors: Vec<Header<'x, Error>>,
    pub(crate) has_dkim_errors: bool,
    #[cfg(feature = "arc")]
    pub(crate) has_arc_errors: bool,
    pub(crate) has_dkim2_errors: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StreamedBody {
    pub(crate) len: u64,
    pub(crate) dkim2: Digests,
    /// SHA-256 over every body byte, independent of any signature. It lets
    /// two streamed snapshots with different bodies be distinguished even
    /// when the message carried no signature that asked for a body hash.
    pub(crate) digest: [u8; 32],
}

impl StreamedBody {
    pub(crate) fn has_dkim2_digests(&self, wanted: impl IntoIterator<Item = Dkim2Hash>) -> bool {
        wanted
            .into_iter()
            .all(|hash| matches!(self.dkim2.get(hash.index()), Some(Some(_))))
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        if self.len != other.len || self.digest != other.digest {
            return false;
        }
        if self.dkim2.iter().all(|digest| digest.is_none())
            && other.dkim2.iter().all(|digest| digest.is_none())
        {
            return true;
        }

        // A length alone does not prove that two bodies are identical. At
        // least one digest must be present on both sides, and every digest
        // present on both sides must agree. A message with only a SHA-256
        // digest therefore cannot be declared identical to a message with
        // only a SHA-512 digest.
        let mut shared = false;
        for (a, b) in self.dkim2.iter().zip(&other.dkim2) {
            if let (Some(a), Some(b)) = (a, b) {
                if a.as_ref() != b.as_ref() {
                    return false;
                }
                shared = true;
            }
        }
        shared
    }
}

impl<'x> AsRef<AuthenticatedMessage<'x>> for AuthenticatedMessage<'x> {
    fn as_ref(&self) -> &AuthenticatedMessage<'x> {
        self
    }
}

impl<'x> TryFrom<&'x [u8]> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x [u8]) -> Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::Parse)
    }
}

impl<'x> TryFrom<&'x Vec<u8>> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x Vec<u8>) -> Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::Parse)
    }
}

impl<'x> AuthenticatedMessage<'x> {
    /// Returns the identity of this exact parsed message revision.
    ///
    /// The identity covers the parsed header snapshot, the body offset and
    /// every body hash computed for the message. Streamed messages contribute
    /// their body length and a digest of the full body, so two messages that
    /// share a header section but differ in body evidence have different
    /// identities.
    pub fn identity(&self) -> MessageIdentity {
        let mut hasher = IdentityHasher::new();
        hasher.update_u64(self.body_offset as u64);
        hasher.update_u64(self.headers.len() as u64);
        for (name, value) in &self.headers {
            hasher.update_u64(name.len() as u64);
            hasher.update(name);
            hasher.update_u64(value.len() as u64);
            hasher.update(value);
        }

        // The order in which body hashes were discovered is an implementation
        // detail. Hash them sorted so equivalent snapshots built by the
        // buffered and streamed parsers keep the same semantic evidence.
        let mut named_body_hashes: Vec<(Canonicalization, HashAlgorithm, u64)> = Vec::new();
        for header in &self.dkim_headers {
            named_body_hashes.push((
                header.header.cb,
                HashAlgorithm::from(header.header.a),
                header.header.l,
            ));
        }
        #[cfg(feature = "arc")]
        for header in &self.ams_headers {
            named_body_hashes.push((
                header.header.cb,
                HashAlgorithm::from(header.header.a),
                header.header.l,
            ));
        }
        let mut body_hashes: Vec<_> = self.body_hashes.iter().collect();
        body_hashes.retain(|entry| {
            let entry = *entry;
            named_body_hashes.iter().any(|named| {
                named.0 == entry.0 && named.1 == entry.1 && named.2 == entry.2
            })
        });
        body_hashes.sort_unstable_by(|a, b| {
            let a = *a;
            let b = *b;
            (a.0 as u8, a.1 as u64, a.2, &a.3).cmp(&(b.0 as u8, b.1 as u64, b.2, &b.3))
        });
        hasher.update_u64(body_hashes.len() as u64);
        for entry in body_hashes {
            hasher.update_u64(entry.0 as u64);
            hasher.update_u64(entry.1 as u64);
            hasher.update_u64(entry.2);
            hasher.update_u64(entry.3.len() as u64);
            hasher.update(&entry.3);
        }

        hasher.update_u64(self.dkim_headers.len() as u64);
        hasher.update_u64(self.dkim2_signatures.len() as u64);
        hasher.update_u64(self.dkim2_instances.len() as u64);
        hasher.update_u64(self.errors.len() as u64);
        hasher.update_u64(self.has_dkim_errors as u64);
        hasher.update_u64(self.has_dkim2_errors as u64);
        #[cfg(feature = "arc")]
        {
            hasher.update_u64(self.ams_headers.len() as u64);
            hasher.update_u64(self.as_headers.len() as u64);
            hasher.update_u64(self.aar_headers.len() as u64);
            hasher.update_u64(self.has_arc_errors as u64);
        }

        let body_len = if let Some(body) = &self.streamed_body {
            body.len
        } else {
            self.raw_message
                .get(self.body_offset as usize..)
                .unwrap_or_default()
                .len() as u64
        };
        hasher.update_u64(body_len);
        let body_digest = self.body_digest();
        hasher.update(&body_digest);

        let message_len = self.raw_message.len() as u64
            + self
                .streamed_body
                .as_deref()
                .map_or(0, |body| body.len);
        MessageIdentity::new(hasher.finish(), message_len)
    }

    /// Alias for [`identity`](Self::identity).
    pub fn message_instance(&self) -> MessageIdentity {
        self.identity()
    }

    /// Alias for [`identity`](Self::identity).
    pub fn fingerprint(&self) -> MessageIdentity {
        self.identity()
    }

    /// Alias for [`identity`](Self::identity).
    pub fn verification_identity(&self) -> MessageIdentity {
        self.identity()
    }

    /// Returns the SHA-256 digest of the message body.
    ///
    /// Buffered messages hash the body bytes directly; streamed messages
    /// return the digest collected while the body was read.
    pub fn body_digest(&self) -> [u8; 32] {
        if let Some(body) = &self.streamed_body {
            return body.digest;
        }
        let digest = Sha256::digest(
            self.raw_message
                .get(self.body_offset as usize..)
                .unwrap_or_default(),
        );
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        bytes
    }

    /// Parses a raw RFC 5322 message in strict mode.
    ///
    /// Equivalent to [`parse_with_opts(raw_message, None, true)`](Self::parse_with_opts).
    /// Returns `None` when no header could be parsed.
    pub fn parse(raw_message: &'x [u8]) -> Option<Self> {
        Self::parse_with_opts(raw_message, None, true)
    }

    /// Builds an `AuthenticatedMessage` from a message already parsed by
    /// [`mail_parser`], reusing its header offsets instead of parsing again.
    ///
    /// `raw_message` must be the exact bytes `parsed` was parsed from. Only the
    /// headers of the root part are read. `strict` has the same meaning as in
    /// [`parse_with_opts`](Self::parse_with_opts).
    pub fn from_parsed<'y>(parsed: &'y Message<'x>, raw_message: &'x [u8], strict: bool) -> Self {
        let root = parsed.root_part();
        let headers = root.headers();
        let mut message = AuthenticatedMessage {
            raw_message,
            body_offset: root.offset_body(),
            headers: Vec::with_capacity(headers.len()),
            ..Default::default()
        };
        let raw_range = |from: u32, to: u32| {
            raw_message
                .get(from as usize..to as usize)
                .unwrap_or_default()
        };

        for header in headers {
            let name = raw_range(
                header.offset_field(),
                header.offset_start().saturating_sub(1),
            );
            let value = raw_range(header.offset_start(), header.offset_end());

            match header.name() {
                HeaderName::From => {
                    message.parse_from(header.value().as_address());
                }
                HeaderName::Date => {
                    message.date_header_present = true;
                }
                HeaderName::Received => {
                    message.received_headers_count += 1;
                }
                HeaderName::MessageId => {
                    message.message_id_header_present = true;
                }
                HeaderName::DkimSignature => {
                    message.parse_dkim(name, value, strict);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcAuthenticationResults => {
                    message.parse_aar(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcSeal => {
                    message.parse_as(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcMessageSignature => {
                    message.parse_ams(name, value, strict);
                }
                HeaderName::Dkim2Signature => {
                    message.parse_dkim2_signature(name, value);
                }
                HeaderName::MessageInstance => {
                    message.parse_dkim2_instance(name, value);
                }
                _ => (),
            }

            message.headers.push((name, value))
        }

        message.finalize()
    }

    /// Parses a raw RFC 5322 message.
    ///
    /// `prepend_headers`, when set, holds header lines that are parsed as if
    /// they appeared before the headers of `raw_message` (for example,
    /// headers added by the receiving MTA but not yet written to the message).
    ///
    /// When `strict` is `true`, `DKIM-Signature` and `ARC-Message-Signature`
    /// headers that carry a body length tag (`l=`) are rejected and recorded
    /// as errors ([`DkimError::BodyLengthTag`](crate::dkim::DkimError::BodyLengthTag)
    /// for DKIM, `ArcError::BodyLengthTag` for ARC),
    /// because a length limit lets an attacker append content to a signed
    /// body (RFC 6376 Section 8.2). When `false`, such signatures are kept.
    ///
    /// Returns `None` when no header could be parsed.
    pub fn parse_with_opts(
        raw_message: &'x [u8],
        prepend_headers: Option<&'x [u8]>,
        strict: bool,
    ) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            raw_message,
            headers: Vec::with_capacity(EXPECTED_HEADER_COUNT),
            ..Default::default()
        };

        if let Some(headers) = prepend_headers {
            message.parse_headers(headers, strict);
        }

        let body_offset = message.parse_headers(raw_message, strict);

        if !message.headers.is_empty() {
            if let Some(offset) = body_offset {
                message.body_offset = offset as u32;
            } else {
                message.body_offset = raw_message.len() as u32;
            }
            Some(message.finalize())
        } else {
            None
        }
    }

    pub(crate) fn parse_streamed(
        header_section: &'x [u8],
        prepend_headers: Option<&'x [u8]>,
        strict: bool,
        body_hashes: &[(Canonicalization, HashAlgorithm, u64, Vec<u8>)],
        body: StreamedBody,
    ) -> crate::Result<Self> {
        let mut message = AuthenticatedMessage {
            raw_message: header_section,
            headers: Vec::with_capacity(EXPECTED_HEADER_COUNT),
            ..Default::default()
        };

        if let Some(headers) = prepend_headers {
            message.parse_headers(headers, strict);
        }
        message.parse_headers(header_section, strict);
        if message.headers.is_empty() {
            return Err(Error::Parse);
        }
        // Two entries for the same canonicalization, algorithm and length
        // must describe the same body. Otherwise the snapshot mixes evidence
        // from two different bodies and no signature can safely claim it.
        for (index, hash) in body_hashes.iter().enumerate() {
            let conflicts = body_hashes[..index].iter().any(|other| {
                let other = *other;
                other.0 == hash.0
                    && other.1 == hash.1
                    && other.2 == hash.2
                    && other.3 != hash.3
            });
            if conflicts {
                return Err(Error::BodyNotAvailable);
            }
        }
        message.body_offset = header_section.len() as u32;
        let mut message = message.finalize();
        for (cb, ha, l, bh) in &mut message.body_hashes {
            *bh = body_hashes
                .iter()
                .find(|(c, h, len, _)| c == cb && h == ha && len == l)
                .map(|(_, _, _, bh)| bh.clone())
                .ok_or(Error::BodyNotAvailable)?;
        }
        for hash in body_hashes {
            if !message
                .body_hashes
                .iter()
                .any(|(c, h, l, _)| (c, h, l) == (&hash.0, &hash.1, &hash.2))
            {
                message.body_hashes.push(hash.clone());
            }
        }
        let named = message
            .dkim2_instances
            .iter()
            .flat_map(|header| &header.header.hashes)
            .filter_map(|hash| hash.name.known());
        if !body.has_dkim2_digests(named) {
            return Err(Error::BodyNotAvailable);
        }
        message.streamed_body = Some(Box::new(body));
        Ok(message)
    }

    /// Returns `true` when the message came from a
    /// [`MessageStream`](crate::stream::MessageStream): its body was hashed
    /// and is not held, so [`raw_body`](Self::raw_body) is empty and
    /// [`raw_message`](Self::raw_message) is the header section.
    pub fn is_streamed(&self) -> bool {
        self.streamed_body.is_some()
    }

    pub(crate) fn streamed_dkim2_digests(
        &self,
        wanted: impl IntoIterator<Item = Dkim2Hash>,
    ) -> crate::Result<Option<Digests>> {
        match self.streamed_body.as_deref() {
            Some(body) if body.has_dkim2_digests(wanted) => Ok(Some(body.dkim2.clone())),
            Some(_) => Err(Error::BodyNotAvailable),
            None => Ok(None),
        }
    }

    fn parse_headers(&mut self, headers: &'x [u8], strict: bool) -> Option<usize> {
        let mut headers = HeaderParser::new(headers);

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    self.parse_dkim(name, value, strict);
                    name
                }
                AuthenticatedHeader::D2s(name) => {
                    self.parse_dkim2_signature(name, value);
                    name
                }
                AuthenticatedHeader::D2i(name) => {
                    self.parse_dkim2_instance(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Aar(name) => {
                    self.parse_aar(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Ams(name) => {
                    self.parse_ams(name, value, strict);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::As(name) => {
                    self.parse_as(name, value);
                    name
                }
                AuthenticatedHeader::From(name) => {
                    self.parse_from(HeaderForm::Addresses.parse(value).value().as_address());
                    name
                }
                AuthenticatedHeader::Other(name) => name,
            };

            self.headers.push((name, value));
        }

        self.received_headers_count += headers.num_received;
        self.message_id_header_present |= headers.has_message_id;
        self.date_header_present |= headers.has_date;

        headers.body_offset()
    }

    fn parse_dkim(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        match dkim::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                self.dkim_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_dkim_error(name, value, Error::Dkim(dkim::DkimError::BodyLengthTag));
            }
            Err(err) => self.push_dkim_error(name, value, err),
        }
    }

    fn parse_dkim2_signature(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::Signature::parse(value) {
            Ok(signature) => self
                .dkim2_signatures
                .push(Header::new(name, value, signature)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    fn parse_dkim2_instance(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::MessageInstance::parse(value) {
            Ok(instance) => self
                .dkim2_instances
                .push(Header::new(name, value, instance)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_aar(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::ArcAuthResults::parse(value) {
            Ok(results) => self.aar_headers.push(Header::new(name, value, results)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_ams(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        match arc::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                self.ams_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_arc_error(name, value, Error::Arc(arc::ArcError::BodyLengthTag));
            }
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_as(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::Seal::parse(value) {
            Ok(seal) => self.as_headers.push(Header::new(name, value, seal)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    fn push_dkim_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    fn push_dkim2_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim2_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    #[cfg(feature = "arc")]
    fn push_arc_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_arc_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    fn parse_from(&mut self, addresses: Option<AddressList<'_>>) {
        if let Some(addresses) = addresses {
            self.from.extend(
                addresses
                    .mailboxes()
                    .filter_map(|mailbox| mailbox.address().map(str::to_lowercase)),
            );
        }
    }

    fn finalize(mut self) -> Self {
        let body = self
            .raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default();

        for (cb, ha, l, bh) in &mut self.body_hashes {
            *bh = ha.hash(cb.canonical_body(body, *l)).as_ref().to_vec();
        }

        #[cfg(feature = "arc")]
        if !self.as_headers.is_empty() && !self.has_arc_errors {
            self.as_headers.sort_unstable_by_key(|h| h.header.i);
            self.ams_headers.sort_unstable_by_key(|h| h.header.i);
            self.aar_headers.sort_unstable_by_key(|h| h.header.i);
        }

        self.dkim2_signatures.sort_unstable_by_key(|h| h.header.i);
        self.dkim2_instances.sort_unstable_by_key(|h| h.header.m);

        self
    }

    /// Returns the number of `Received` headers in the message.
    pub fn received_headers_count(&self) -> usize {
        self.received_headers_count
    }

    /// Returns `true` if the message has a `Message-ID` header.
    pub fn has_message_id_header(&self) -> bool {
        self.message_id_header_present
    }

    /// Returns `true` if the message has a `Date` header.
    pub fn has_date_header(&self) -> bool {
        self.date_header_present
    }

    /// Returns the raw message bytes, headers and body.
    pub fn raw_message(&self) -> &[u8] {
        self.raw_message
    }

    /// Returns the raw header section of the message, including the blank
    /// line that separates it from the body when one is present. Prepended
    /// headers are not included.
    pub fn raw_headers(&self) -> &[u8] {
        self.raw_message
            .get(..self.body_offset as usize)
            .unwrap_or_default()
    }

    /// Returns every header as a `(name, value)` pair of raw bytes, in message
    /// order. Prepended headers come first. The name excludes the colon; the
    /// value keeps its folding and the trailing line ending.
    pub fn headers(&self) -> &[(&'x [u8], &'x [u8])] {
        &self.headers
    }

    /// Returns the raw message body. Empty when the message has no body.
    pub fn raw_body(&self) -> &[u8] {
        self.raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default()
    }

    /// Returns the byte offset of the body within
    /// [`raw_message`](Self::raw_message).
    pub fn body_offset(&self) -> usize {
        self.body_offset as usize
    }

    /// Returns the lowercased addresses found in the `From` header, including
    /// the members of address groups.
    pub fn from_addresses(&self) -> &[String] {
        &self.from
    }

    /// Returns the first `From` address, or an empty string if there is none.
    /// This is the author address used for DMARC (RFC 9989).
    pub fn first_from_address(&self) -> &str {
        self.from.first().map_or("", |f| f.as_str())
    }

    /// Returns the `DKIM-Signature` headers (RFC 6376) that parsed
    /// successfully, in message order.
    pub fn dkim_signatures(&self) -> &[Header<'x, dkim::Signature>] {
        &self.dkim_headers
    }

    /// Returns the `DKIM2-Signature` headers that parsed successfully, sorted
    /// by signature sequence number (`i=` tag).
    pub fn dkim2_signatures(&self) -> &[Header<'x, dkim2::Signature>] {
        &self.dkim2_signatures
    }

    /// Returns the `Message-Instance` headers that parsed successfully,
    /// sorted by revision number (`m=` tag).
    pub fn dkim2_instances(&self) -> &[Header<'x, dkim2::MessageInstance>] {
        &self.dkim2_instances
    }

    /// Returns the `ARC-Message-Signature` headers that parsed successfully
    /// (feature `arc`). They are sorted by instance number (`i=` tag) unless
    /// an ARC header failed to parse.
    #[cfg(feature = "arc")]
    pub fn arc_message_signatures(&self) -> &[Header<'x, arc::Signature>] {
        &self.ams_headers
    }

    /// Returns the `ARC-Seal` headers that parsed successfully (feature
    /// `arc`), sorted like [`arc_message_signatures`](Self::arc_message_signatures).
    #[cfg(feature = "arc")]
    pub fn arc_seals(&self) -> &[Header<'x, arc::Seal>] {
        &self.as_headers
    }

    /// Returns the `ARC-Authentication-Results` headers that parsed
    /// successfully (feature `arc`), sorted like
    /// [`arc_message_signatures`](Self::arc_message_signatures).
    #[cfg(feature = "arc")]
    pub fn arc_authentication_results(&self) -> &[Header<'x, arc::ArcAuthResults>] {
        &self.aar_headers
    }

    /// Returns the authentication headers that could not be parsed or were
    /// rejected, each paired with the reason.
    pub fn errors(&self) -> &[Header<'x, Error>] {
        &self.errors
    }

    /// Returns `true` if a `DKIM-Signature` header failed to parse or was
    /// rejected (including by
    /// [`retain_dkim_signatures`](Self::retain_dkim_signatures)).
    pub fn has_dkim_errors(&self) -> bool {
        self.has_dkim_errors
    }

    /// Returns `true` if a `DKIM2-Signature` or `Message-Instance` header
    /// failed to parse.
    pub fn has_dkim2_errors(&self) -> bool {
        self.has_dkim2_errors
    }

    /// Returns `true` if an ARC header failed to parse or was rejected. The
    /// ARC verifier reports a broken chain in that case.
    #[cfg(feature = "arc")]
    pub fn has_arc_errors(&self) -> bool {
        self.has_arc_errors
    }

    /// Keeps only the DKIM signatures accepted by `accept`.
    ///
    /// `accept` is called once for every parsed `DKIM-Signature`. Signatures
    /// for which it returns `Err` are removed from
    /// [`dkim_signatures`](Self::dkim_signatures); the error is added to
    /// [`errors`](Self::errors) as [`Error::Dkim`] and
    /// [`has_dkim_errors`](Self::has_dkim_errors) becomes `true`, so
    /// `verify_dkim` reports each rejected signature as `neutral` with that
    /// error. Use it to apply a local policy, such as rejecting `rsa-sha1`
    /// signatures, before verification.
    pub fn retain_dkim_signatures(
        &mut self,
        mut accept: impl FnMut(&dkim::Signature) -> Result<(), dkim::DkimError>,
    ) {
        let errors = &mut self.errors;
        let mut rejected = false;
        self.dkim_headers
            .retain(|header| match accept(&header.header) {
                Ok(()) => true,
                Err(err) => {
                    errors.push(Header::new(header.name, header.value, Error::Dkim(err)));
                    rejected = true;
                    false
                }
            });
        self.has_dkim_errors |= rejected;
    }
}

#[cfg(test)]
mod tests {
    use super::AuthenticatedMessage;

    #[test]
    fn message_identity_tracks_the_body_snapshot() {
        let first = AuthenticatedMessage::parse(
            b"From: a@example.org\r\nSubject: x\r\n\r\nfirst body\r\n",
        )
        .unwrap();
        let second = AuthenticatedMessage::parse(
            b"From: a@example.org\r\nSubject: x\r\n\r\nthird body\r\n",
        )
        .unwrap();
        let reparsed = AuthenticatedMessage::parse(
            b"From: a@example.org\r\nSubject: x\r\n\r\nfirst body\r\n",
        )
        .unwrap();

        assert_ne!(first.identity(), second.identity());
        assert_eq!(first.identity(), reparsed.identity());
        assert_eq!(
            first.identity().digest(),
            reparsed.identity().digest()
        );
    }
}
