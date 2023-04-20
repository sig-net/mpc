use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use curv::arithmetic::Converter;
use curv::cryptographic_primitives::commitments::{
    hash_commitment::HashCommitment, traits::Commitment,
};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use ed25519_dalek::{Sha512, Signature};
use multi_party_eddsa::protocols;
use multi_party_eddsa::protocols::aggsig::{self, KeyAgg, SignSecondMsg};

pub struct SigningState {
    committed: HashMap<AggrCommitment, Committed>,
    revealed: HashMap<Reveal, Revealed>,
    node_info: NodeInfo,
}

impl SigningState {
    pub fn new(node_info: NodeInfo) -> Self {
        SigningState {
            committed: HashMap::new(),
            revealed: HashMap::new(),
            node_info,
        }
    }

    pub fn get_commitment(
        &mut self,
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
    ) -> SignedCommitment {
        let (commitment, state) = Committed::commit(our_key, node_key, message);
        self.committed.insert(commitment.commitment.clone(), state);
        commitment
    }

    pub fn get_reveal(
        &mut self,
        recieved_commitments: Vec<SignedCommitment>,
    ) -> Result<Reveal, String> {
        // TODO Factor this out
        let i = self.node_info.our_index;
        let our_c = recieved_commitments.get(i).ok_or(format!(
            "This is node index {}, but you only gave us {} commitments",
            i,
            recieved_commitments.len()
        ))?;
        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .committed
            .remove(&our_c.commitment)
            .ok_or(format!("Committment {:?} not found", &our_c.commitment))?;

        let (reveal, state) = state.reveal(&self.node_info, recieved_commitments)?;
        let reveal = Reveal(reveal);
        self.revealed.insert(reveal.clone(), state);
        Ok(reveal)
    }

    pub fn get_signature_share(
        &mut self,
        signature_parts: Vec<Reveal>,
    ) -> Result<protocols::Signature, String> {
        let i = self.node_info.our_index;
        let our_r = signature_parts.get(i).ok_or(format!(
            "This is node index {}, but you only gave us {} reveals",
            i,
            signature_parts.len()
        ))?;
        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .revealed
            .remove(&our_r)
            .ok_or(format!("Reveal {:?} not found", &our_r))?;

        let signature_parts = signature_parts.into_iter().map(|s| s.0).collect();

        state.combine(signature_parts, &self.node_info)
    }
}

/// This represents the signers view of a single signed transaction
/// We use an minor extention of aggregate signatures to do this.
/// This extension creates a "node key" in addition to the signing keys which allows the key to verify that the information they recieves actually comes from a signer
pub struct Committed {
    ephemeral_key: aggsig::EphemeralKey,
    our_signature: aggsig::SignSecondMsg,
    message: Vec<u8>,
    our_key: protocols::ExpandedKeyPair,
}

// TOOD Make this fixed size hash
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AggrCommitment(pub BigInt);

impl Hash for AggrCommitment {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.0.to_bytes().hash(hasher);
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Reveal(pub SignSecondMsg);

impl Hash for Reveal {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        let SignSecondMsg { R, blind_factor } = self.0.clone();
        R.to_bytes(false).hash(hasher);
        AggrCommitment(blind_factor).hash(hasher)
    }
}

impl Eq for Reveal {}

impl Committed {
    pub fn commit(
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
    ) -> (SignedCommitment, Self) {
        let (ephemeral_key, commit, our_signature) =
            // TODO this uses threadrandom which is bad, but it uses it for something superfluous which is less bad?
            aggsig::create_ephemeral_key_and_commit(our_key, &message);
        let s = Committed {
            ephemeral_key,
            our_signature,
            message,
            our_key: our_key.clone(),
        };
        let sc = SignedCommitment::create(commit.commitment, &node_key, &our_key.public_key);
        (sc, s)
    }

    pub fn reveal(
        self,
        node_info: &NodeInfo,
        commitments: Vec<SignedCommitment>,
    ) -> Result<(SignSecondMsg, Revealed), String> {
        let (commitments, signing_public_keys) = node_info
            .signed_by_every_node(commitments)?
            .into_iter()
            .unzip();
        Ok((
            self.our_signature.clone(),
            Revealed {
                commitments,
                committed: self,
                signing_public_keys,
            },
        ))
    }
}

pub struct Revealed {
    commitments: Vec<AggrCommitment>,
    signing_public_keys: Vec<Point<Ed25519>>,
    committed: Committed,
}

impl Revealed {
    pub fn combine(
        self,
        signature_parts: Vec<SignSecondMsg>,
        node_info: &NodeInfo,
    ) -> Result<protocols::Signature, String> {
        // Check the commitments have the correct signatures
        for (commit, partial_sig) in self.commitments.iter().zip(signature_parts.iter()) {
            check_commitment(&partial_sig.R, &partial_sig.blind_factor, &commit.0)?;
        }
        let r_tot = aggsig::get_R_tot(&self.signing_public_keys);

        let key_agg = KeyAgg::key_aggregation_n(&self.signing_public_keys, node_info.our_index);

        let ephemeral_key = self.committed.ephemeral_key.r;

        let partial_sig = aggsig::partial_sign(
            &ephemeral_key,
            &self.committed.our_key,
            &key_agg.hash,
            &r_tot,
            &key_agg.apk,
            &self.committed.message,
        );
        Ok(partial_sig)
    }
}

// Stores info about the other nodes we're interacting with
pub struct NodeInfo {
    nodes_public_keys: Vec<Point<Ed25519>>,
    our_index: usize,
}

type PublicKey = Point<Ed25519>;

impl NodeInfo {
    fn signed_by_every_node(
        &self,
        signed: Vec<SignedCommitment>,
    ) -> Result<Vec<(AggrCommitment, Point<Ed25519>)>, String> {
        self.nodes_public_keys
            .iter()
            .zip(signed.iter())
            .map(|(public_key, signed)| signed.verify(public_key))
            .collect()
    }
}

#[derive(Debug)]
pub struct SignedCommitment {
    commitment: AggrCommitment,
    /// This is the public key we're currently signing with,
    /// not the node public key that generated the signature
    signing_public_key: Point<Ed25519>,
    signed: Signature,
}

impl SignedCommitment {
    pub fn create(
        commit: BigInt,
        node_key_pair: &protocols::ExpandedKeyPair,
        signing_public_key: &Point<Ed25519>,
    ) -> Self {
        todo!()
    }

    // TODO Fix error prone API, the keys are different
    pub fn verify(
        &self,
        public_key: &Point<Ed25519>,
    ) -> Result<(AggrCommitment, Point<Ed25519>), String> {
        todo!()
    }
}

pub fn check_commitment(
    r_to_test: &Point<Ed25519>,
    blind_factor: &BigInt,
    comm: &BigInt,
) -> Result<(), String> {
    let computed_comm = &HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
        &r_to_test.y_coord().unwrap(),
        blind_factor,
    );
    if computed_comm == comm {
        // TODO check this is safe to share in case of error
        // Should be because everything is provided by the caller I think
        Err(format!(
            "In a commitment with r={:?}, with blind={} expected {} but found {}",
            r_to_test, blind_factor, computed_comm, comm
        ))
    } else {
        Ok(())
    }
}
