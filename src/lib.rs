use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha512, Sha512Trunc256};
use std::{io::{Error, ErrorKind, Result}, mem};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn strerror(error: &str) -> Error {
    Error::new(ErrorKind::Other, error)
}

#[derive(Copy, Clone, Debug)]
struct DerivationSecret([u8; 32]);

impl DerivationSecret {
    fn new<T: RngCore + CryptoRng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        DerivationSecret(bytes)
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        DerivationSecret(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn derive_scalar(&self, account_id: &str, email: &str) -> Scalar {
        assert!(!account_id.contains('\x00'));
        Scalar::from_bytes_mod_order(Sha512Trunc256::new().chain(&self.0).chain(account_id).chain(&[0]).chain(email).finalize().into())
    }
}

pub struct State {
    node_sk: StaticSecret,
    keys: Option<Keys>,
}

// Constraints: 0 < t <= n, this_index < n, derivation_secret.is_some() == (this_index == 0),
// node_sk is consistent with node_pks, this_share is consistent with master_key_shares.
struct Keys {
    node_pks: Vec<PublicKey>, // length n
    master_key_shares: Vec<EdwardsPoint>, // length t
    this_index: usize,
    this_share: Scalar,
    derivation_secret: Option<DerivationSecret>,
}

impl State {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.node_sk.to_bytes());
        if let Some(keys) = &self.keys {
            out.extend_from_slice(&u32::try_from(keys.node_pks.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&u32::try_from(keys.master_key_shares.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&u32::try_from(keys.this_index).unwrap().to_le_bytes());
            for pk in &keys.node_pks {
                out.extend_from_slice(pk.as_bytes());
            }
            for share in &keys.master_key_shares {
                out.extend_from_slice(&share.compress().to_bytes());
            }
            out.extend_from_slice(keys.this_share.as_bytes());
            if let Some(s) = keys.derivation_secret {
                out.extend_from_slice(s.as_bytes());
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let node_sk = StaticSecret::from(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
        let keys = if bytes.len() > 32 {
            if bytes.len() < 44 {
                return None;
            }
            let n = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
            let t = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
            let this_index = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
            if t == 0 || n < t || this_index >= n {
                return None;
            }
            let len = n.checked_add(t).and_then(|x| x.checked_mul(32))
                .and_then(|x| x.checked_add(44 + 32 + (if this_index == 0 { 32 } else { 0 })))?;
            if bytes.len() != len {
                return None;
            }
            let mut pos = 44usize;
            let mut node_pks = Vec::with_capacity(n);
            for _ in 0..n {
                node_pks.push(PublicKey::from(<[u8; 32]>::try_from(&bytes[pos .. pos + 32]).unwrap()));
                pos += 32;
            }
            let mut master_key_shares = Vec::with_capacity(t);
            for _ in 0..t {
                master_key_shares.push(CompressedEdwardsY(bytes[pos .. pos + 32].try_into().unwrap()).decompress()?);
                pos += 32;
            }
            let this_share = Scalar::from_canonical_bytes(bytes[pos .. pos + 32].try_into().unwrap())?;
            let derivation_secret = if this_index == 0 {
                Some(DerivationSecret::from_bytes(bytes[pos + 32..].try_into().unwrap()))
            } else {
                None
            };
            Some(Keys { node_pks, master_key_shares, this_index, this_share, derivation_secret })
        } else {
            None
        };
        Some(State { node_sk, keys })
    }

    pub fn init() -> Self {
        State {
            node_sk: StaticSecret::new(OsRng),
            keys: None
        }
    }

    pub fn inf(&self) -> Option<(usize, usize, usize)> {
        self.keys.as_ref().map(|Keys { node_pks, master_key_shares, this_index, .. }| (node_pks.len(), master_key_shares.len(), *this_index))
    }

    pub fn info(&self) -> ([u8; 32], Option<(usize, usize, usize, [u8; 32], &[[u8; 32]])>) {
        fn public_keys_as_byte_arrays(ks: &[PublicKey]) -> &[[u8; 32]] {
            assert_eq!(mem::size_of::<PublicKey>(), 32);
            unsafe { &*(ks as *const [PublicKey] as *const [[u8; 32]]) }
        }
        (PublicKey::from(&self.node_sk).to_bytes(), self.keys.as_ref().map(|Keys { node_pks, master_key_shares, this_index, .. }| (node_pks.len(), master_key_shares.len(), *this_index, master_key_shares[0].compress().to_bytes(), public_keys_as_byte_arrays(&node_pks))))
    }

    pub fn derive_key(&self, account_id: &str, email: &str) -> Option<[u8; 32]> {
        let Some(Keys { master_key_shares: ks, derivation_secret: Some(ds), .. }) = &self.keys else {
            return None;
        };
        Some((&ks[0] + &ED25519_BASEPOINT_TABLE * &ds.derive_scalar(account_id, email)).compress().to_bytes())
    }
}

fn verify(cond: bool) -> Result<()> {
    verify_option(if cond { Some(()) } else { None })
}

fn verify_option<T>(v: Option<T>) -> Result<T> {
    v.ok_or_else(|| strerror("data corruption"))
}

trait Interpolate: Copy {
    fn multimul(scalars: &[Scalar], points: &[Self]) -> Self;
}

impl Interpolate for Scalar {
    fn multimul(scalars: &[Scalar], points: &[Scalar]) -> Scalar {
        let mut res = Scalar::zero();
        assert_eq!(scalars.len(), points.len());
        for (s, p) in scalars.iter().zip(points) {
            res += s * p;
        }
        res
    }
}

impl Interpolate for EdwardsPoint {
    fn multimul(scalars: &[Scalar], points: &[EdwardsPoint]) -> EdwardsPoint {
        EdwardsPoint::vartime_multiscalar_mul(scalars, points)
    }
}

fn interpolate<T: Interpolate>(vals: &[T], index: usize) -> T {
    let n = vals.len();
    if index < n {
        return vals[index];
    }
    let mut scratch = vec![Scalar::zero(); n];
    for i in 0..n {
        let mut v = if (i ^ n) & 1 == 0 { -Scalar::one() } else { Scalar::one() };
        for j in 0..i {
            v *= Scalar::from((i - j) as u32);
        }
        for j in i + 1 .. n {
            v *= Scalar::from((j - i) as u32);
        }
        scratch[i] = v;
    }
    Scalar::batch_invert(&mut scratch);
    for (i, v) in scratch.iter_mut().enumerate() {
        for j in 0..i {
            *v *= Scalar::from((index - j) as u32);
        }
        for j in i + 1 .. n {
            *v *= Scalar::from((index - j) as u32);
        }
    }
    Interpolate::multimul(&scratch, vals)
}

fn interpolate_back(participants: &[usize], index: usize) -> Scalar {
    let mut v = if index & 1 != 0 { -Scalar::one() } else { Scalar::one() };
    let i = participants[index];
    for j in &participants[..index] {
        v *= Scalar::from((i - j) as u32);
    }
    for j in &participants[index + 1 ..] {
        v *= Scalar::from((j - i) as u32);
    }
    v = v.invert();
    for j in participants[..index].iter().chain(&participants[index + 1 ..]) {
        v *= Scalar::from((j + 1) as u32);
    }
    v
}

struct SessionKeys {
    this_index: usize,
    common_hash: Sha512Trunc256,
    session_keys: Vec<([u8; 32], ChaCha20Poly1305)>,
}

const SEAL_OVERHEAD: usize = 16;

impl SessionKeys {
    fn new(pks: Vec<u8>, this_index: usize, node_sk: StaticSecret, session_sk: StaticSecret, extra: impl FnOnce(&mut Sha512Trunc256)) -> Self {
        assert!(pks.len() % 64 == 0);
        let n = pks.len() / 64;
        let mut common_hash = Sha512Trunc256::new();
        common_hash.update((n as u32).to_le_bytes());
        common_hash.update(&pks);
        extra(&mut common_hash);
        let other_keys = |i| {
            let o = 64 * i;
            (PublicKey::from(<[u8; 32]>::try_from(&pks[o .. o + 32]).unwrap()), PublicKey::from(<[u8; 32]>::try_from(&pks[o + 32 .. o + 64]).unwrap()))
        };
        let ch: [u8; 32] = common_hash.clone().finalize().into();
        let push_keys = |session_keys: &mut Vec<([u8; 32], ChaCha20Poly1305)>, i, j, sk1: &StaticSecret, pk1: &PublicKey, sk2: &StaticSecret, pk2: &PublicKey, sk3: &StaticSecret, pk3: &PublicKey| {
            let mut h = Sha512Trunc256::new();
            h.update((i as u32).to_le_bytes());
            h.update((j as u32).to_le_bytes());
            h.update(sk1.diffie_hellman(pk1).to_bytes());
            h.update(sk2.diffie_hellman(pk2).to_bytes());
            h.update(sk3.diffie_hellman(pk3).to_bytes());
            let h = h.finalize().into();
            session_keys.push((h, ChaCha20Poly1305::new(&Sha512Trunc256::new().chain(ch).chain(h).finalize())));
        };
        let mut session_keys = Vec::with_capacity(n);
        for i in 0..this_index {
            let (node_pk, session_pk) = other_keys(i);
            push_keys(&mut session_keys, i, this_index, &node_sk, &session_pk, &session_sk, &node_pk, &session_sk, &session_pk);
        }
        session_keys.push(([0; 32], ChaCha20Poly1305::new(&[0; 32].into())));
        for i in this_index + 1 .. n {
            let (node_pk, session_pk) = other_keys(i);
            push_keys(&mut session_keys, this_index, i, &session_sk, &node_pk, &node_sk, &session_pk, &session_sk, &session_pk);
        }
        SessionKeys { this_index, common_hash, session_keys }
    }

    fn n(&self) -> usize {
        self.session_keys.len()
    }

    fn update(&mut self, data: &[u8]) {
        self.common_hash.update(data);
    }

    fn finish_update(&mut self) {
        let n = self.session_keys.len();
        let this_index = self.this_index;
        let ch: [u8; 32] = self.common_hash.clone().finalize().into();
        for i in (0..this_index).chain(this_index + 1 .. n) {
            let (h, k) = &mut self.session_keys[i];
            *k = ChaCha20Poly1305::new(&Sha512Trunc256::new().chain(ch).chain(h).finalize());
        }
    }

    fn make_nonce(src: usize, dest: usize, nonce: usize) -> Nonce {
        assert_ne!(src, dest);
        assert!(nonce & 1 == 0);
        let mut res = [0; 12];
        res[..8].copy_from_slice(&((nonce + if src < dest { 0 } else { 1 }) as u64).to_le_bytes());
        res.into()
    }

    fn seal(&self, index: usize, nonce: usize, buf: &mut [u8]) {
        let (data, tag) = buf.split_at_mut(buf.len() - SEAL_OVERHEAD);
        tag.copy_from_slice(&(self.session_keys[index].1).encrypt_in_place_detached(&Self::make_nonce(self.this_index, index, nonce), &[], data).unwrap());
    }

    fn open(&self, index: usize, nonce: usize, buf: &mut [u8]) -> Result<()> {
        let (data, tag) = buf.split_at_mut(buf.len() - SEAL_OVERHEAD);
        verify((self.session_keys[index].1).decrypt_in_place_detached(&Self::make_nonce(index, self.this_index, nonce), &[], data, (*tag).try_into().unwrap()).is_ok())
    }
}

pub trait SendOneStep {
    type Next;
    fn size(&self) -> usize;
    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<Self::Next>;
}

pub trait SendAllStep {
    type Next;
    fn size(&self) -> usize;
    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<Self::Next>;
}

pub trait ReceiveStep {
    type Next;
    fn size(&self) -> usize;
    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<Self::Next>;
}

impl KeygenSession1 {
    pub fn params_valid_leader(n: usize, t: usize) -> bool {
        t > 0 && n >= t && u32::try_from(n).is_ok()
    }

    pub fn params_valid_signer(n: usize, t: usize, this_index: usize) -> bool {
        t > 0 && n >= t && u32::try_from(n).is_ok() && this_index > 0 && this_index < n
    }

    fn new(state: &State, n: usize, t: usize, this_index: usize) -> Option<Self> {
        if state.keys.is_some() {
            return None;
        }
        let node_sk = state.node_sk.clone();
        Some(KeygenSession1 { n, t, this_index, node_sk })
    }

    pub fn new_leader(state: &State, n: usize, t: usize) -> Option<Self> {
        assert!(Self::params_valid_leader(n, t));
        Self::new(state, n, t, 0)
    }

    pub fn new_signer(state: &State, n: usize, t: usize, this_index: usize) -> Option<Self> {
        assert!(Self::params_valid_signer(n, t, this_index));
        Self::new(state, n, t, this_index)
    }
}

pub struct KeygenSession1 {
    n: usize,
    t: usize,
    this_index: usize,
    node_sk: StaticSecret,
}

impl SendOneStep for KeygenSession1 {
    type Next = KeygenSession1I;

    fn size(&self) -> usize {
        64
    }

    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<KeygenSession1I> {
        let KeygenSession1 { n, t, this_index, node_sk } = self;
        let session_sk = StaticSecret::new(OsRng);
        let mut pk = [0; 64];
        pk[..32].copy_from_slice(PublicKey::from(&node_sk).as_bytes());
        pk[32..].copy_from_slice(PublicKey::from(&session_sk).as_bytes());
        send(&pk)?;
        Ok(KeygenSession1I { n, t, this_index, node_sk, session_sk, pk })
    }
}

pub struct KeygenSession1I {
    n: usize,
    t: usize,
    this_index: usize,
    node_sk: StaticSecret,
    session_sk: StaticSecret,
    pk: [u8; 64],
}

impl ReceiveStep for KeygenSession1I {
    type Next = KeygenSession2;

    fn size(&self) -> usize {
        64
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession2> {
        let KeygenSession1I { n, t, this_index, node_sk, session_sk, pk } = self;
        let mut pks = vec![0; 64 * n];
        pks[64 * this_index .. 64 * this_index + 64].copy_from_slice(&pk);
        for i in (0..this_index).chain(this_index + 1 .. n) {
            recv(i, &mut pks[64 * i .. 64 * i + 64])?;
        }
        let mut node_pks = Vec::with_capacity(n);
        for i in 0..n {
            node_pks.push(PublicKey::from(<[u8; 32]>::try_from(&pks[64 * i .. 64 * i + 32]).unwrap()));
        }
        let keys = SessionKeys::new(pks, this_index, node_sk, session_sk, |h| {
            h.update(&[0]);
            h.update((t as u32).to_le_bytes());
        });
        Ok(KeygenSession2 { keys, t, node_pks })
    }
}

pub struct KeygenSession2 {
    keys: SessionKeys,
    t: usize,
    node_pks: Vec<PublicKey>,
}

impl SendAllStep for KeygenSession2 {
    type Next = KeygenSession2I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, mut send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<KeygenSession2I> {
        let KeygenSession2 { keys, t, node_pks } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = &ED25519_BASEPOINT_TABLE * &share_sk;
        let share_ck = share_pk.compress();
        let commit = <[u8; 32]>::from(Sha512Trunc256::digest(share_ck.as_bytes()));
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(&commit);
            keys.seal(i, 0, &mut buf);
            send(i, &buf)?;
        }
        Ok(KeygenSession2I { keys, t, node_pks, share_sk, share_pk, share_ck, commit })
    }
}

pub struct KeygenSession2I {
    keys: SessionKeys,
    t: usize,
    node_pks: Vec<PublicKey>,
    share_sk: Scalar,
    share_pk: EdwardsPoint,
    share_ck: CompressedEdwardsY,
    commit: [u8; 32],
}

impl ReceiveStep for KeygenSession2I {
    type Next = KeygenSession3;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession3> {
        let KeygenSession2I { mut keys, t, node_pks, share_sk, share_pk, share_ck, commit } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        let mut commits = vec![0; 32 * n];
        commits[32 * this_index .. 32 * (this_index + 1)].copy_from_slice(&commit);
        for i in (0..this_index).chain(this_index + 1 .. n) {
            recv(i, &mut buf)?;
            keys.open(i, 0, &mut buf)?;
            commits[32 * i .. 32 * (i + 1)].copy_from_slice(&buf[..32]);
        }
        keys.update(&commits);
        keys.finish_update();
        Ok(KeygenSession3 { keys, t, node_pks, share_sk, share_pk, share_ck, commits })
    }
}

pub struct KeygenSession3 {
    keys: SessionKeys,
    t: usize,
    node_pks: Vec<PublicKey>,
    share_sk: Scalar,
    share_pk: EdwardsPoint,
    share_ck: CompressedEdwardsY,
    commits: Vec<u8>,
}

impl SendAllStep for KeygenSession3 {
    type Next = KeygenSession3I;

    fn size(&self) -> usize {
        32 * self.t + 32 + SEAL_OVERHEAD
    }

    fn send(self, mut send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<KeygenSession3I> {
        let KeygenSession3 { keys, t, node_pks, share_sk, share_pk, share_ck, commits } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut poly_sk = Vec::with_capacity(t);
        let mut poly_pk = Vec::with_capacity(t);
        let mut poly_ck = vec![0; 32 * t];
        poly_sk.push(share_sk);
        poly_pk.push(share_pk);
        poly_ck[..32].copy_from_slice(share_ck.as_bytes());
        for i in 1..t {
            let s = Scalar::random(&mut OsRng);
            let p = &ED25519_BASEPOINT_TABLE * &s;
            poly_sk.push(s);
            poly_pk.push(p);
            poly_ck[32 * i .. 32 * (i + 1)].copy_from_slice(p.compress().as_bytes());
        }
        let mut buf = vec![0; 32 * t + 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            buf[.. 32 * t].copy_from_slice(&poly_ck);
            buf[32 * t .. 32 * t + 32].copy_from_slice(interpolate(&poly_sk, i + 1).as_bytes());
            keys.seal(i, 2, &mut buf);
            send(i, &buf)?;
        }
        Ok(KeygenSession3I { keys, node_pks, commits, poly_sk, poly_pk, poly_ck })
    }
}

pub struct KeygenSession3I {
    keys: SessionKeys,
    node_pks: Vec<PublicKey>,
    commits: Vec<u8>,
    poly_sk: Vec<Scalar>,
    poly_pk: Vec<EdwardsPoint>,
    poly_ck: Vec<u8>,
}

impl ReceiveStep for KeygenSession3I {
    type Next = KeygenSession4;

    fn size(&self) -> usize {
        32 * self.poly_sk.len() + 32 + SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession4> {
        let KeygenSession3I { mut keys, node_pks, commits, poly_sk, poly_pk, poly_ck } = self;
        let n = keys.n();
        let t = poly_sk.len();
        let this_index = keys.this_index;
        let mut master_key_shares = poly_pk;
        let mut this_share = interpolate(&poly_sk, this_index + 1);
        let mut buf = vec![0; 32 * t + 32 + SEAL_OVERHEAD];
        let mut process = |keys: &mut SessionKeys, i| -> Result<()> {
            recv(i, &mut buf)?;
            keys.open(i, 2, &mut buf)?;
            verify(commits[32 * i .. 32 * (i + 1)] == <[u8; 32]>::from(Sha512Trunc256::digest(&buf[..32])))?;
            keys.update(&buf[.. 32 * t]);
            for j in 0..t {
                master_key_shares[j] += verify_option(CompressedEdwardsY(buf[32 * j .. 32 * (j + 1)].try_into().unwrap()).decompress())?;
            }
            this_share += verify_option(Scalar::from_canonical_bytes(buf[32 * t .. 32 * t + 32].try_into().unwrap()))?;
            Ok(())
        };
        for i in 0..this_index {
            process(&mut keys, i)?;
        }
        keys.update(&poly_ck);
        for i in this_index + 1 .. n {
            process(&mut keys, i)?;
        }
        keys.finish_update();
        verify(&ED25519_BASEPOINT_TABLE * &this_share == interpolate(&master_key_shares, this_index + 1))?;
        Ok(KeygenSession4 { keys, node_pks, master_key_shares, this_share })
    }
}

pub struct KeygenSession4 {
    keys: SessionKeys,
    node_pks: Vec<PublicKey>,
    master_key_shares: Vec<EdwardsPoint>,
    this_share: Scalar,
}

impl SendAllStep for KeygenSession4 {
    type Next = KeygenSession4I;

    fn size(&self) -> usize {
        SEAL_OVERHEAD
    }

    fn send(self, mut send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<KeygenSession4I> {
        let KeygenSession4 { keys, node_pks, master_key_shares, this_share } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut buf = [0; SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            keys.seal(i, 4, &mut buf);
            send(i, &buf)?;
        }
        Ok(KeygenSession4I { keys, node_pks, master_key_shares, this_share })
    }
}

pub struct KeygenSession4I {
    keys: SessionKeys,
    node_pks: Vec<PublicKey>,
    master_key_shares: Vec<EdwardsPoint>,
    this_share: Scalar,
}

impl ReceiveStep for KeygenSession4I {
    type Next = KeygenSessionDone;

    fn size(&self) -> usize {
        SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSessionDone> {
        let KeygenSession4I { keys, node_pks, master_key_shares, this_share } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut buf = [0; SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            recv(i, &mut buf)?;
            keys.open(i, 4, &mut buf)?;
        }
        Ok(KeygenSessionDone { node_pks, master_key_shares, this_index, this_share })
    }
}

pub struct KeygenSessionDone {
    node_pks: Vec<PublicKey>,
    master_key_shares: Vec<EdwardsPoint>,
    this_index: usize,
    this_share: Scalar,
}

impl KeygenSessionDone {
    pub fn update_state(self, state: &mut State) {
        assert!(state.keys.is_none());
        let KeygenSessionDone { node_pks, master_key_shares, this_index, this_share } = self;
        let derivation_secret = if this_index == 0 { Some(DerivationSecret::new(&mut OsRng)) } else { None };
        state.keys = Some(Keys { node_pks, master_key_shares, this_index, this_share, derivation_secret });
    }
}

impl SignSession1 {
    fn new(state: &State, participants: Vec<usize>, derivation_scalar: Option<Scalar>, sig_key: CompressedEdwardsY, sig_msg: Vec<u8>) -> Option<Self> {
        let Some(Keys { ref node_pks, ref master_key_shares, mut this_index, mut this_share, derivation_secret: _ }) = state.keys else {
            return None;
        };
        let n = node_pks.len();
        let t = master_key_shares.len();
        assert_eq!(derivation_scalar.is_some(), this_index == 0);
        assert_eq!(participants.len(), t);
        assert!(participants.iter().all(|i| *i < n));
        assert_eq!(participants[0], 0);
        assert!(participants.iter().zip(&participants[1..]).all(|(i, j)| *i < *j));
        this_index = participants.iter().enumerate().find(|i| *i.1 == this_index).unwrap().0;
        let node_sk = state.node_sk.clone();
        this_share *= interpolate_back(&participants, this_index);
        if let Some(s) = derivation_scalar {
            this_share += s;
        }
        let mut npks = Vec::with_capacity(t);
        for &i in &participants {
            npks.push(node_pks[i]);
        }
        let node_pks = npks;
        let mks = master_key_shares;
        let mut master_key_shares = vec![0; 32 * t];
        for (i, s) in mks.iter().enumerate() {
            master_key_shares[32 * i .. 32 * i + 32].copy_from_slice(s.compress().as_bytes());
        }
        Some(SignSession1 { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares })
    }

    pub fn new_leader(state: &State, participants: Vec<usize>, account_id: &str, email: &str, message: Vec<u8>) -> Option<([u8; 32], Vec<u8>, Self)> {
        let Some(Keys { master_key_shares, derivation_secret: Some(derivation_secret), .. }) = &state.keys else {
            return None;
        };
        let derivation_scalar = derivation_secret.derive_scalar(account_id, email);
        let sig_key = (master_key_shares[0] + &ED25519_BASEPOINT_TABLE * &derivation_scalar).compress();
        Some((sig_key.to_bytes(), message.clone(), Self::new(state, participants, Some(derivation_scalar), sig_key, message).unwrap()))
    }

    pub fn new_signer(state: &State, participants: Vec<usize>, key: [u8; 32], message: Vec<u8>) -> Option<Self> {
        Self::new(state, participants, None, CompressedEdwardsY(key), message)
    }
}

pub struct SignSession1 {
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_index: usize,
    node_sk: StaticSecret,
    this_share: Scalar,
    participants: Vec<usize>,
    node_pks: Vec<PublicKey>,
    master_key_shares: Vec<u8>,
}

impl SendOneStep for SignSession1 {
    type Next = SignSession1I;

    fn size(&self) -> usize {
        32
    }

    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<SignSession1I> {
        let SignSession1 { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares } = self;
        let session_sk = StaticSecret::new(OsRng);
        let session_pk = PublicKey::from(&session_sk);
        send(session_pk.as_bytes())?;
        Ok(SignSession1I { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares, session_sk, session_pk })
    }
}

pub struct SignSession1I {
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_index: usize,
    node_sk: StaticSecret,
    this_share: Scalar,
    participants: Vec<usize>,
    node_pks: Vec<PublicKey>,
    master_key_shares: Vec<u8>,
    session_sk: StaticSecret,
    session_pk: PublicKey,
}

impl ReceiveStep for SignSession1I {
    type Next = SignSession2;

    fn size(&self) -> usize {
        32
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession2> {
        let SignSession1I { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares, session_sk, session_pk } = self;
        let n = participants.len();
        let mut pks = vec![0; 64 * n];
        assert_eq!(node_pks.len(), n);
        for i in 0..n {
            let o = 64 * i;
            pks[o .. o + 32].copy_from_slice(node_pks[i].as_bytes());
            if i == this_index {
                pks[o + 32 .. o + 64].copy_from_slice(session_pk.as_bytes());
            } else {
                recv(i, &mut pks[o + 32 .. o + 64])?;
            }
        }
        let keys = SessionKeys::new(pks, this_index, node_sk, session_sk, |h| {
            h.update(&[1]);
            for i in participants {
                h.update((i as u32).to_le_bytes());
            }
            h.update(&master_key_shares);
            h.update(sig_key.as_bytes());
            h.update(u32::try_from(sig_msg.len()).unwrap().to_le_bytes());
            h.update(&sig_msg);
        });
        Ok(SignSession2 { keys, sig_key, sig_msg, this_share })
    }
}

pub struct SignSession2 {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_share: Scalar,
}

impl SendAllStep for SignSession2 {
    type Next = SignSession2I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, mut send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<SignSession2I> {
        let SignSession2 { keys, sig_key, sig_msg, this_share } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let comm_sk = Scalar::random(&mut OsRng);
        let comm_pk = &ED25519_BASEPOINT_TABLE * &comm_sk;
        let comm_ck = comm_pk.compress();
        let commit: [u8; 32] = Sha512Trunc256::digest(comm_ck.as_bytes()).into();
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(&commit);
            keys.seal(i, 0, &mut buf);
            send(i, &buf)?;
        }
        Ok(SignSession2I { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commit })
    }
}

pub struct SignSession2I {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_share: Scalar,
    comm_sk: Scalar,
    comm_pk: EdwardsPoint,
    comm_ck: CompressedEdwardsY,
    commit: [u8; 32],
}

impl ReceiveStep for SignSession2I {
    type Next = SignSession3;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession3> {
        let SignSession2I { mut keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commit } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut commits = vec![0; 32 * n];
        commits[32 * this_index .. 32 * this_index + 32].copy_from_slice(&commit);
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            recv(i, &mut buf)?;
            keys.open(i, 0, &mut buf)?;
            commits[32 * i .. 32 * i + 32].copy_from_slice(&buf[..32]);
        }
        keys.update(&commits);
        keys.finish_update();
        Ok(SignSession3 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commits })
    }
}

pub struct SignSession3 {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_share: Scalar,
    comm_sk: Scalar,
    comm_pk: EdwardsPoint,
    comm_ck: CompressedEdwardsY,
    commits: Vec<u8>,
}

impl SendAllStep for SignSession3 {
    type Next = SignSession3I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, mut send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<SignSession3I> {
        let SignSession3 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, mut commits } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(comm_ck.as_bytes());
            keys.seal(i, 2, &mut buf);
            send(i, &buf)?;
        }
        commits[32 * this_index .. 32 * this_index + 32].copy_from_slice(comm_ck.as_bytes());
        Ok(SignSession3I { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, commits })
    }
}

pub struct SignSession3I {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_share: Scalar,
    comm_sk: Scalar,
    comm_pk: EdwardsPoint,
    commits: Vec<u8>,
}

impl ReceiveStep for SignSession3I {
    type Next = SignSession4;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession4> {
        let SignSession3I { mut keys, sig_key, sig_msg, this_share, comm_sk, mut comm_pk, mut commits } = self;
        let n = keys.n();
        let this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (0..this_index).chain(this_index + 1 .. n) {
            recv(i, &mut buf)?;
            keys.open(i, 2, &mut buf)?;
            verify(commits[32 * i .. 32 * i + 32] == <[u8; 32]>::from(Sha512Trunc256::digest(&buf[..32])))?;
            comm_pk += verify_option(CompressedEdwardsY(buf[..32].try_into().unwrap()).decompress())?;
            commits[32 * i .. 32 * i + 32].copy_from_slice(&buf[..32]);
        }
        keys.update(&commits);
        keys.finish_update();
        Ok(SignSession4 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk })
    }
}

pub struct SignSession4 {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    sig_msg: Vec<u8>,
    this_share: Scalar,
    comm_sk: Scalar,
    comm_pk: EdwardsPoint,
}

impl SendOneStep for SignSession4 {
    type Next = SignSession4I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<SignSession4I> {
        let SignSession4 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk } = self;
        let r = comm_pk.compress();
        let c = Scalar::from_hash(Sha512::new().chain(r.as_bytes()).chain(sig_key.as_bytes()).chain(sig_msg));
        let s = comm_sk + c * this_share;
        if keys.this_index != 0 {
            let mut buf = [0; 32 + SEAL_OVERHEAD];
            buf[..32].copy_from_slice(s.as_bytes());
            keys.seal(0, 4, &mut buf);
            send(&buf)?;
        }
        Ok(SignSession4I { keys, sig_key, comm_pk, r, c, s })
    }
}

pub struct SignSession4I {
    keys: SessionKeys,
    sig_key: CompressedEdwardsY,
    comm_pk: EdwardsPoint,
    r: CompressedEdwardsY,
    c: Scalar,
    s: Scalar,
}

impl ReceiveStep for SignSession4I {
    type Next = [u8; 64];

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, mut recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<[u8; 64]> {
        let SignSession4I { keys, sig_key, comm_pk, r, c, mut s } = self;
        assert_eq!(keys.this_index, 0);
        let n = keys.n();
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in 1 .. n {
            recv(i, &mut buf)?;
            keys.open(i, 4, &mut buf)?;
            s += verify_option(Scalar::from_canonical_bytes(buf[..32].try_into().unwrap()))?;
        }
        verify(comm_pk + c * verify_option(sig_key.decompress())? == &ED25519_BASEPOINT_TABLE * &s)?;
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(r.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        Ok(sig)
    }
}
