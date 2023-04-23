use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::constants::EDWARDS_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha512_256;
use x52219_dalek::{PublicKey, StaticSecret};

#[derive(Copy, Clone, Debug)]
struct DerivationSecret([u8; 32]);

impl DerivationSecret {
    fn new<T: RngCore + CryptoRng>(csprng: T) -> Self {
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

    fn derive_scalar(&self, account_id, email: &str) -> Scalar {
        assert!(!account_id.contains('\x00'));
        Scalar::from_bytes_mod_order(Sha512_256::new().chain_update(&self.0).chain_update(account_id).chain_update(&[0]).chain_update(email).finalize().into())
    }
}

pub struct State {
    node_sk: StaticSecret;
    keys: Option<Keys>;
}

// Constraints: 0 < t <= n, this_index < n, derivation_secret.is_some() == (this_index == 0),
// node_sk is consistent with node_pks, this_share is consistent with master_key_shares.
struct Keys {
    node_pks: Vec<PublicKey>; // length n
    master_key_shares: Vec<EdwardsPoint>; // length t
    this_index: usize,
    this_share: Scalar,
    derivation_secret: Option<DerivationSecret>;
}

impl State {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.node_sk.to_bytes());
        if let Some(keys) = self.keys {
            out.extend_from_slice(&u32::try_from(keys.node_pks.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&u32::try_from(keys.master_key_shares.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&u32::try_from(keys.this_index).unwrap().to_le_bytes());
            for pk in keys.node_pks {
                out.extend_from_slice(pk.as_bytes());
            }
            for share in keys.master_key_shares {
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
        let node_sk = StaticSecret::from(*(&[u8; 32])::try_from(bytes[..32]).unwrap());
        let keys = if bytes.len() > 32 {
            if bytes.len() < 44 {
                return None;
            }
            let n = u32::from_le_bytes(*bytes[32..36].try_into().unwrap()) as usize;
            let t = u32::from_le_bytes(*bytes[36..40].try_into().unwrap()) as usize;
            let this_index = u32::from_le_bytes(*bytes[40..44].try_into().unwrap()) as usize;
            if t == 0 || n < t || this_index >= n {
                return None;
            }
            let len = n.checked_add(t).and_then(|x| 32.checked_mul(x))
                .and_then(|x| (44 + 32 + (if this_index == 0 { 32 } else { 0 })).checked_add(x))?;
            if bytes.len() != len {
                return None;
            }
            let mut pos = 44usize;
            let mut node_pks = Vec::with_capacity(n);
            for _ in ..n {
                node_pks.push(PublicKey::from(*bytes[pos .. pos + 32].try_into().unwrap()));
                pos += 32;
            }
            let mut master_key_shares = Vec::with_capacity(t);
            for _ in ..t {
                master_key_shares.push(CompressedEdwardsY(*bytes[pos .. pos + 32].try_into().unwrap()).decompress()?);
                pos += 32;
            }
            let this_share = Scalar::from_canonical_bytes(*bytes[pos .. pos + 32].try_into().unwrap())?;
            let derivation_secret = if this_index == 0 {
                Some(DerivationSecret::from_bytes(*bytes[pos + 32..].try_into().unwrap()))
            } else {
                None
            };
            Some(Keys { node_pks, master_key_shares, this_index, this_share, derivation_secret })
        } else {
            None
        }
        Some(State { node_sk, keys })
    }

    pub fn init() -> Self {
        State {
            node_sk: StaticSecret::new(OsRng)
            keys: None
        }
    }

    pub fn inf(&self) -> Option<(usize, usize, usize)> {
        self.keys.map(|Keys { node_pks, master_key_shares, this_index, .. }| (node_pks.len(), master_key_shares.len(), this_index))
    }

    pub fn info(&self) -> ([u8; 32], Option<(usize, usize, usize, [u8; 32], &[[u8; 32]])> {
        fn public_keys_as_byte_arrays(ks: &[PublicKey]) -> &[[u8; 32]] {
            assert_eq!(mem::size_of<PublicKey>(), 32);
            unsafe { mem::transmute(ks) }
        }
        (PublicKey::from(self.node_sk).to_bytes(), self.keys.map(|Keys { node_pks, master_key_shares, this_index, .. }| (node_pks.len(), master_key_shares.len(), this_index, master_key_shares[0].compress().to_bytes(), public_keys_as_byte_arrays(node_pks))))
    }

    pub fn derive_key(&self, account_id, email: &str) -> Option<[u8; 32]> {
        let Some(Keys { master_key_shares: ks, derivation_secret: Some(ds) }) = self.keys else {
            return None;
        }
        Some((&ks[0] + &EDWARDS_BASEPOINT_TABLE * ds.derive_scalar(account_id, email)).compress().to_bytes())
    }
}

fn verify(cond: bool) -> Result<()> {
    verivy_option(if cond { Some(()) } else { None })
}

fn<T> verify_option(v: Option<T>) -> Result<T> {
    v.ok_or_else(|| Error::other("data corruption"))
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
    const minusone = -Scalar::one();
    let mut scratch = vec![Scalar::zero(); n];
    for i in ..n {
        let mut v = if (i ^ n) & 1 == 0 { minusone } else { Scalar::one() };
        for j in ..i {
            v *= Scalar::from(i - j);
        }
        for j in i + 1 .. n {
            v *= Scalar::from(j - i);
        }
        scratch[i] = v;
    }
    Scalar::batch_invert(&mut scratch);
    for (i, v) in scratch.iter_mut().enumerate() {
        for j in ..i {
            *v *= Scalar::from(index - j);
        }
        for j in i + 1 .. n {
            *v *= Scalar::from(index - j);
        }
    }
    multimul(scratch, vals)
}

fn interpolate_back(participants: &[usize], index: usize) -> Scalar {
    let mut v = if index & 1 != 0 { -Scalar::one() } else { Scalar::one() };
    let i = participants[index];
    for j in participents[..index] {
        v *= Scalar::from(i - j);
    }
    for j in participants[index + 1 ..] {
        v *= Scalar::from(j - i);
    }
    v = v.invert();
    for j in participants[..index].iter().chain(participants[index + 1 ..]) {
        v *= Scalar::from(j + 1);
    }
    v
}

struct SessionKeys {
    this_index: usize;
    common_hash: Sha512_256;
    session_keys: Vec<([u8; 32], ChaCha20Poly1305)>;
}

const SEAL_OVERHEAD: usize = 16;
fn make_nonce(src, dest, nonce: usize) -> Nonce<ChaCha20Poly1305> {
    assert_ne!(src, dest);
    assert!(nonce & 1 == 0);
    let mut res = [0; 12];
    res[..8].extend_from_slice(((nonce + if src < dest { 0 } else { 1 }) as u64).to_le_bytes());
    res.into()
}

impl SessionKeys {
    fn new(pks: Vec<u8>, this_index: usize, node_sk: StaticSecret, session_sk: StaticSecret, extra: impl FnOnce(&mut Sha512_256)) -> Self {
        assert!(pks.len() % 64 == 0);
        let n = pks.len() / 64;
        let mut common_hash = Sha512_256::new();
        common_hash.update((n as u32).to_le_bytes());
        common_hash.update(pks);
        extra(&mut common_hash);
        let other_keys = |i| {
            let o = 64 * i;
            (PublicKey::from(pks[o .. o + 32].try_into().unwrap()), PublicKey::from(pks[o + 32 .. o + 64].try_into().unwrap()))
        };
        let ch = common_hash.clone().finalize().into();
        let push_keys = |session_keys, i, j, sk1, pk1, sk2, pk2, sk3, pk3| {
            let mut h = Sha512_256::new();
            h.update((i as u32).to_le_bytes());
            h.update((j as u32).to_le_bytes());
            h.update(sk1.diffie_hellman(pk1).to_bytes());
            h.update(sk2.diffie_hellman(pk2).to_bytes());
            h.update(sk3.diffie_hellman(pk3).to_bytes());
            let h = h.finalize().into();
            session_keys.push((h, ChaCha20Poly1305::new(Sha512_256::new().chain_update(ch).chain_update(h).finalize())))
        }
        let mut session_keys = Vec::with_capacity(n);
        for i in ..this_index {
            let (node_pk, session_pk) = other_keys(i);
            push_keys(session_keys, i, this_index, node_sk, session_pk, session_sk, node_pk, session_sk, session_pk);
        }
        session_keys.push(([0; 32], ChaCha20Poly1305::new([0; 32])));
        for i in this_index + 1 .. n {
            let (node_pk, session_pk) = other_keys(i);
            push_keys(session_keys, this_index, i, session_sk, node_pk, node_sk, session_pk, session_sk, session_pk);
        }
        SessionKeys { this_index, common_hash, session_keys }
    }

    fn n(&self) {
        self.session_keys.len()
    }

    fn update(&mut self, data: &[u8]) {
        self.common_hash.update(data);
    }

    fn finish_update(&mut self) {
        let n = self.session_keys.len(), this_index = self.this_index;
        let ch = self.common_hash.clone().finalize().into();
        for i in (..this_index).chain(this_index + 1 .. n) {
            let (h, k) = &mut self.session_keys[i];
            *k = ChaCha20Poly1305::new(Sha512_256::new().chain_update(ch).chain_update(h).finalize());
        }
    }

    fn seal(&self, index, nonce: usize, buf: &mut [u8]) {
        let l = buf.len() - SEAL_OVERHEAD;
        buf[l..].copy_from_slice((self.session_keys[index].1).encrypt_in_place_detached(make_nonce(self.this_index, index), &[], buf[..l]).unwrap());
    }

    fn open(&self, index, nonce: usize, buf: &mut [u8]) -> Result<()> {
        let l = buf.len() - SEAL_OVERHEAD;
        verify((self.session_keys[index].1).decrypt_in_place_detached(make_nonce(index, self.this_index), &[], buf[..l], buf[l..].try_into().unwrap()).is_ok())
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
    fn send(self, send: impl FnOnce(usize, &[u8]) -> Result<()>) -> Result<Self::Next>;
}

pub trait ReceiveStep {
    type Next;
    fn size(&self) -> usize;
    fn recv(self, recv: impl FnOnce(usize, &mut [u8]) -> Result<()>) -> Result<Self::Next>;
}

impl KeygenSession1 {
    pub fn params_valid_leader(n, t: usize) -> bool {
        t > 0 && n >= t && u32::try_from(n).is_ok()
    }

    pub fn params_valid_signer(n, t, this_index: usize) -> bool {
        t > 0 && n >= t && u32::try_from(n).is_ok() && this_index > 0 && this_index < n
    }

    fn new(state: &State, n, t, this_index: usize) -> Option<Self> {
        if state.keys.is_some() {
            return None;
        }
        let node_sk = keys.node_sk;
        Some(KeygenSession1 { n, t, this_index, node_sk })
    }

    pub fn new_leader(state: &State, n, t: usize) -> Option<Self> {
        assert!(params_valid_leader(n, t);
        new(state, n, t, 0)
    }

    pub fn new_signer(state: &State, n, t, this_index: usize) -> Option<Self> {
        assert!(params_valid_signer(n, t, this_index);
        new(state, n, t, this_index)
    }
}

pub struct KeygenSession1 {
    n, t, this_index: usize;
    node_sk: StaticSecret;
}

impl SendOneStep for KeygenSession1 {
    type Next = KeygenSession1I;

    fn size(&self) -> usize {
        64
    }

    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<KeygenSession1I> {
        let KeygenSession1 { n, t, this_index, node_sk } = self;
        let session_sk = ReusableSecret::new(OsRng);
        let mut pk = [0; 64];
        pk[..32].copy_from_slice(PublicKey::from(base.node_sk).to_bytes());
        pk[32..].copy_from_slice(PublicKey::from(session_sk).to_bytes());
        send(pk)?
        Ok(KeygenSession1I { n, t, this_index, node_sk, session_sk, pk })
    }
}

pub struct KeygenSession1I {
    n, t, this_index: usize;
    node_sk: StaticSecret;
    session_sk: ReusableSecret;
    pk: [u8; 64];
}

impl ReceiveStep for KeygenSession1I {
    type Next = KeygenSession2;

    fn size(&self) -> usize {
        64
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession2> {
        let KeygenSession1I { n, t, this_index, node_sk, session_sk, pk } = self;
        let mut pks = vec![0; 64 * n];
        pks[this_index] = pk;
        for i in (..this_index).chain(this_index + 1 .. n) {
            recv(i, pks[64 * i .. 64 * i + 64])?;
        }
        let mut node_pks = Vec::with_capacity(n);
        for i in ..n {
            node_pks.push(PublicKey::from(pks[64 * i .. 64 * i + 32].try_into().unwrap()));
        }
        let keys = SessionKeys::new(pks, this_index, node_sk, session_sk, |h| {
            h.update(&[0]);
            h.update((t as u32).to_le_bytes());
        });
        Ok(KeygenSession2 { keys, t, node_pks })
    }
}

pub struct KeygenSession2 {
    keys: SessionKeys;
    t: usize;
    node_pks: Vec<PublicKey>
}

impl SendAllStep for KeygenSession2 {
    type Next = KeygenSession2I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<KeygenSession2I> {
        let KeygenSession2 { keys, t, node_pks } = self;
        let n = keys.n(), this_index = keys.this_index;
        let share_sk = Scalar::random(OsRng);
        let share_pk = &EDWARDS_BASEPOINT_TABLE * share_sk;
        let share_ck = share_pk.compress();
        let commit = [u8; 32]::from(Sha512_256::digest(share_ck.as_bytes()));
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(commit);
            keys.seal(i, 0, buf);
            send(i, buf)?;
        }
        Ok(KeygenSession2I { keys, t, node_pks, share_sk, share_pk, share_ck, commit })
    }
}

pub struct KeygenSession2I {
    keys: SessionKeys;
    t: usize;
    node_pks: Vec<PublicKey>
    share_sk: Scalar;
    share_pk: EdwardsPoint;
    share_ck: CompressedEdwardsY;
    commit: [u8; 32];
}

impl ReceiveStep for KeygenSession2I {
    type Next = KeygenSession3;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession3> {
        let KeygenSession2I { keys, t, node_pks, share_sk, share_pk, share_ck, commit } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        let mut commits = vec![0; 32 * n];
        commits[32 * this_index .. 32 * (this_index + 1)].copy_from_slice(commit);
        for i in (..this_index).chain(this_index + 1 .. n) {
            recv(i, buf)?;
            keys.open(i, 0, buf)?;
            commits[32 * i .. 32 * (i + 1)].copy_from_slice(buf[..32]);
        }
        keys.update(commits);
        keys.finish_update();
        Ok(KeygenSession3 { keys, t, node_pks, share_sk, share_pk, share_ck, commits })
    }
}

pub struct KeygenSession3 {
    keys: SessionKeys;
    t: usize;
    node_pks: Vec<PublicKey>
    share_sk: Scalar;
    share_pk: EdwardsPoint;
    share_ck: CompressedEdwardsY;
    commits: Vec<u8>;
}

impl SendAllStep for KeygenSession3 {
    type Next = KeygenSession3I;

    fn size(&self) -> usize {
        32 * self.base.t + 32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<KeygenSession3I> {
        let KeygenSession3 { keys, t, node_pks, share_sk, share_pk, share_ck, commits } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut poly_sk = Vec::with_capacity(t);
        let mut poly_pk = Vec::with_capacity(t);
        let mut poly_ck = vec![0; 32 * t];
        poly_sk.push(share_sk);
        poly_pk.push(share_pk);
        poly_ck[..32].copy_from_slice(share_ck.as_bytes());
        for i in 1..t {
            let s = Scalar::random(OsRng), p = &EDWARDS_BASEPOINT_TABLE * s;
            poly_sk.push(s);
            poly_pk.push(p);
            poly_ck[32 * i .. 32 * (i + 1)].copy_from_slice(p.compress().as_bytes());
        }
        let mut buf = vec![0; 32 * t + 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            buf[.. 32 * t].copy_from_slice(cpoly);
            buf[32 * t .. 32 * t + 32].copy_from_slice(interpolate(self.poly_sk, i + 1).as_bytes());
            keys.seal(i, 2, buf);
            send(i, buf)?;
        }
        Ok(KeygenSession3I { keys, node_pks, commits, poly_sk, poly_pk, poly_ck })
    }
}

pub struct KeygenSession3I {
    keys: SessionKeys;
    node_pks: Vec<PublicKey>
    commits: Vec<u8>;
    poly_sk: Vec<Scalar>;
    poly_pk: Vec<EdwardsPoint>;
    poly_ck: Vec<u8>;
}

impl ReceiveStep for KeygenSession3I {
    type Next = KeygenSession4;

    fn size(&self) -> usize {
        32 * self.base.t + 32 + SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSession4> {
        let KeygenSession3I { keys, node_pks, commits, poly_sk, poly_pk, poly_ck } = self;
        let n = keys.n(), t = poly_sk.len(), this_index = keys.this_index;
        let mut master_key_shares = poly_pk;
        let mut this_share = interpolate(poly_sk, this_index + 1);
        let mut buf = vec![0; 32 * t + 32 + SEAL_OVERHEAD];
        let process = |keys, i| {
            recv(i, buf)?;
            keys.open(i, 2, buf)?;
            verify(commits[32 * i .. 32 * (i + 1)] == Sha512_256::digest(buf[..32]))?;
            keys.update(buf[.. 32 * t]);
            for j in ..t {
                master_key_shares += verify_option(CompressedEdwardsY([u8; 32]::try_from(buf[32 * j .. 32 * (j + 1)]).unwrap()).decompress())?;
            }
            this_share += verify_option(Scalar::from_canonical_bytes(buf[32 * t .. 32 * t + 32].try_into().unwrap()))?;
            Ok(())
        };
        for i in ..this_index {
            process(keys, i)?;
        }
        keys.update(poly_ck);
        for i in this_index + 1 .. n {
            process(keys, i)?;
        }
        keys.finish_update();
        verify(&EDWARDS_BASEPOINT_TABLE * this_share == interpolate(master_key_shares, this_index + 1))?;
        Ok(KeygenSession4 { keys, node_pks, master_key_shares, this_share })
    }
}

pub struct KeygenSession4 {
    keys: SessionKeys;
    node_pks: Vec<PublicKey>
    master_key_shares: Vec<EdwardsPoint>;
    this_share: Scalar;
}

impl SendAllStep for KeygenSession4 {
    type Next = KeygenSession4I;

    fn size(&self) -> usize {
        SEAL_OVERHEAD
    }

    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<()> {
        let KeygenSession4 { keys, node_pks, master_key_shares, this_share } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut buf = [0; SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            keys.seal(i, 4, buf);
            send(i, buf)?;
        }
        Ok(KeygenSession4I { base, node_pks, master_key_shares, this_share })
    }
}

pub struct KeygenSession4I {
    keys: SessionKeys;
    node_pks: Vec<PublicKey>
    master_key_shares: Vec<EdwardsPoint>;
    this_share: Scalar;
}

impl ReceiveStep for KeygenSession4I {
    type Next = KeygenSessionDone;

    fn size(&self) {
        SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<KeygenSessionDone> {
        let KeygenSession4I { keys, node_pks, master_key_shares, this_share } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut buf = [0; SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            recv(i, buf)?;
            keys.open(i, 2, buf)?;
        }
        Ok(KeygenSessionDone { node_pks, master_key_shares, this_index, this_share })
    }
}

pub struct KeygenSessionDone {
    node_pks: Vec<PublicKey>;
    master_key_shares: Vec<EdwardsPoint>;
    this_index: usize;
    this_share: Scalar;
}

impl KeygenSessionDone {
    fn update_state(self, state: &mut State) {
        assert!(state.keys.is_none());
        let KeygenSessionDone { node_pks, master_key_shares, this_index, this_share } = self;
        let derivation_secret = if this_index == 0 { Some(DerivationSecret::new(OsRng)) } else { None };
        state.keys = Keys { node_pks, master_key_shares, this_index, this_share, derivation_secret };
    }
}

impl SignSession1 {
    fn new(state: &State, participants: Vec<usize>, derivation_scalar: Option<Scalar>, sig_key: CompressedEdwardsY, sig_msg: Vec<u8>) -> Option<Self> {
        let Some(Keys { node_pks, master_key_shares, mut this_index, mut this_share, derivation_secret: _ }) = state.keys else {
            return None;
        };
        let n = node_pks.len(), t = master_key_shares.len();
        assert_eq!(derivation_scalar.is_some(), this_share == 0);
        assert_eq!(participants.len(), t);
        assert!(participants.iter().all(|i| i < n));
        assert_eq!(participants[0], 0);
        assert!(participants.iter().zip(participants[1..]).all(|(i, j)| i < j));
        this_index = participants.find(|i| i == this_index).unwrap();
        let node_sk = state.node_sk;
        this_share *= interpolate_back(participants, this_index);
        if let Some(s) = derivation_scalar {
            this_share += s;
        }
        let npks = Vec::with_capacity(t);
        for i in participants {
            npks.push(node_pks[i]);
        }
        let node_pks = npks;
        Some(SignSession1 { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares })
    }

    pub fn new_leader(state: &State, participants: Vec<usize>, account_id, email: &str, message: Vec<u8>) -> Option<([u8; 32], Vec<u8>, Self)> {
        let Some(Keys { master_key_shares, derivation_secret: Some(derivation_secret), .. }) = state.keys else {
            return None;
        };
        let derivation_scalar = derivation_secret.derive_scalar(account_id, email);
        let sig_key = (master_key_shares[0] + &EDWARDS_BASEPOINT_TABLE * derivation_scalar).compress();
        Some((sig_key.to_bytes(), message.clone(), Self::new(state, participants, Some(derivation_scalar), sig_key, message).unwrap()))
    }

    pub fn new_signer(state: &State, participants: Vec<usize>, key: [u8; 32], message: Vec<u8>) -> Option<Self> {
        Self::new(state, participants, None, CompressedEdwardsY(key), message)
    }
}

pub struct SignSession1 {
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_index: usize;
    node_sk: StaticSecret;
    this_share: Scalar;
    participants: Vec<usize>;
    node_pks: Vec<PublicKey>;
    master_key_shares: Vec<EdwardsPoint>;
}

impl SendOneStep for SignSession1 {
    type Next = SignSession1I;

    fn size(&self) -> usize {
        32
    }

    fn send(self, send: impl FnOnce(usize, &[u8]) -> Result<()>) -> Result<SignSession1I> {
        SignSession1 { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares, derivation_secret } = self;
        let session_sk = ReusableSecret::new(OsRng);
        let session_pk = PublicKey::from(session_sk);
        send(session_pk.as_bytes())?;
        Ok(SignSession1I { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares, session_sk, session_pk })
    }
}

pub struct SignSession1I {
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_index: usize;
    node_sk: StaticSecret;
    this_share: Scalar;
    participants: Vec<usize>;
    node_pks: Vec<PublicKey>;
    master_key_shares: Vec<EdwardsPoint>;
    session_sk: ReusableSecret;
    session_pk: PublicKey;
}

impl ReceiveStep for SignSession1I {
    type Next = SignSession2;

    fn size(&self) -> usize {
        32
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession2> {
        SignSession1I { sig_key, sig_msg, this_index, node_sk, this_share, participants, node_pks, master_key_shares, session_sk, session_pk } = self;
        let n = participants.len();
        let mut pks = vec![0; 64 * n];
        assert_eq!(node_pks.len(), n);
        for i in ..n {
            let o = 64 * i;
            pks[o .. o + 32].copy_from_slice(node_pks[i].as_bytes());
            if i == this_index {
                pks[o + 32 .. o + 64].copy_from_slice(session_pk.as_bytes());
            } else {
                recv(i, pks[o + 32 .. o + 64])?;
            }
        }
        let keys = SessionKeys::new(pks, this_index, node_sk, session_sk, |h| {
            h.update(&[1]);
            for i in participants {
                h.update((i as u32).to_le_bytes());
            }
            for mks in master_key_shares {
                h.update(mks.compress().as_bytes());
            }
            h.update(sig_key.as_bytes());
            h.update(u32::try_from(sig_msg.len()).unwrap().to_le_bytes());
            h.update(sig_msg);
        });
        Ok(SignSession2 { keys, sig_key, sig_msg, this_share })
    }
}

pub struct SignSession2 {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_share: Scalar;
}

impl SendAllStep for SignSession2 {
    type Next = SignSession2I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<SignSession2I> {
        let SignSession2 { keys, sig_key, sig_msg, this_share } = self;
        let n = keys.n(), this_index = keys.this_index;
        let comm_sk = Scalar::random(OsRng);
        let comm_pk = &EDWARDS_BASEPOINT_TABLE * comm_sk;
        let comm_ck = comm_pk.compress();
        let commit = Sha512_256::digest(comm_ck.as_bytes()).into();
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(commit);
            keys.seal(i, 0, buf);
            send(i, buf)?;
        }
        Ok(SignSession2I { keys, sig_key, sig_msg, participants, comm_sk, comm_pk, comm_ck, commit })
    }
}

pub struct SignSession2I {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_share: Scalar;
    comm_sk: Scalar;
    comm_pk: EdwardsPoint;
    comm_ck: CompressedEdwardsY;
    commit: [u8; 32];
}

impl ReceiveStep for SignSession2I {
    type Next = SignSession3;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession3> {
        SignSession2I { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commit } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut commits = vec![0; 32 * n];
        commits[32 * this_index .. 32 * this_index + 32].copy_from_slice(commit);
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            recv(i, buf)?;
            keys.open(i, 0, buf)?;
            commits[32 * i .. 32 * i + 32].copy_from_slice(buf[..32]);
        }
        keys.update(commits);
        keys.finish_update();
        Ok(SignSession3 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commits })
    }
}

pub struct SignSession3 {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_share: Scalar;
    comm_sk: Scalar;
    comm_pk: EdwardsPoint;
    comm_ck: CompressedEdwardsY;
    commits: Vec<u8>;
}

impl SendAllStep for SignSession3 {
    type Next = SignSession3I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<SignSession3I> {
        let SignSession3 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, comm_ck, commits } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            buf[..32].copy_from_slice(comm_ck.as_bytes());
            keys.seal(i, 2, buf);
            send(i, buf)?;
        }
        Ok(SignSession3I { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk, commits })
    }
}

pub struct SignSession3I {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_share: Scalar;
    comm_sk: Scalar;
    comm_pk: EdwardsPoint;
    commits: Vec<u8>;
}

impl ReceiveStep for SignSession3I {
    type Next = SignSession4;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<SignSession4> {
        SignSession3I { keys, sig_key, sig_msg, this_share, comm_sk, mut comm_pk, commits } = self;
        let n = keys.n(), this_index = keys.this_index;
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in (..this_index).chain(this_index + 1 .. n) {
            recv(i, buf)?;
            keys.open(i, 2, buf)?;
            verify(commits[32 * i .. 32 * i + 32] == Sha512_256::digest(buf[..32]).into())?;
            comm_pk += verify_option(CompressedEdwardsY(buf[..32].try_into().unwrap()).decompress())?;
            commits[32 * i .. 32 * i + 32].copy_from_slice(buf[..32]);
        }
        keys.update(commits);
        keys.finish_update();
        Ok(SignSession4 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk })
    }
}

pub struct SignSession4 {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    sig_msg: Vec<u8>;
    this_share: Scalar;
    comm_sk: Scalar;
    comm_pk: EdwardsPoint;
}

impl SendOneStep for SignSession4 {
    type Next = SignSession4I;

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn send(self, send: impl FnOnce(&[u8]) -> Result<()>) -> Result<SignSession4I> {
        let SignSession4 { keys, sig_key, sig_msg, this_share, comm_sk, comm_pk } = self;
        let r = comm_pk.compress();
        let c = Scalar::from_hash(Sha512::new().chain_update(r.as_bytes()).chain_update(sig_key.as_bytes()).chain_update(sig_msg));
        let s = comm_sk + c * this_share;
        if keys.this_index != 0 {
            let mut buf = [0; 32 + SEAL_OVERHEAD];
            buf[..32].copy_from_slice(s.as_bytes());
            keys.seal(0, 4, buf);
            send(buf)?;
        }
        Ok(SignSession4I { keys, sig_key, comm_pk, r, c, s })
    }
}

pub struct SignSession4I {
    keys: SessionKeys;
    sig_key: CompressedEdwardsY;
    comm_pk: EdwardsPoint;
    r: CompressedEdwardsY;
    c: Scalar;
    s: Scalar;
}

impl ReceiveStep for SignSession4I {
    type Next = [u8; 64];

    fn size(&self) -> usize {
        32 + SEAL_OVERHEAD
    }

    fn recv(self, recv: impl FnMut(usize, &mut [u8]) -> Result<()>) -> Result<[u8; 64]> {
        let SignSession4I { keys, sig_key, comm_pk, r, c, mut s } = self;
        assert_eq!(keys.this_index, 0);
        let n = keys.n();
        let mut buf = [0; 32 + SEAL_OVERHEAD];
        for i in 1 .. n {
            recv(i, buf)?;
            keys.open(i, 4, buf)?;
            s += verify_option(Scalar::from_canonical_bytes(buf[..32].try_into().unwrap()))?;
        }
        verify(comm_pk + c * verify_option(sig_key.decompress())? == s * &EDWARDS_BASEPOINT_TABLE)?;
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(r.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        Ok(sig)
    }
}
