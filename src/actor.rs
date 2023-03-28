use actix::prelude::*;
use rand::RngCore;
use std::collections::{btree_map::Entry, BTreeMap};
use threshold_crypto::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

type NodeId = u64;
type TaskId = u64;
type Payload = Vec<u8>;

// A task provided by an external user. Is uniquely identified by its id, but also contains
// the payload itself just for the sake of simplicity (not having to store/request a separate
// mapping).
#[derive(PartialEq, PartialOrd, Eq, Ord, Clone)]
struct Task {
    id: TaskId,
    payload: Payload,
}

// Assuming the same task, this is a collection of known signature shares provided by each
// respective node.
type SigShareSet = BTreeMap<NodeId, SignatureShare>;

// The database schema that validator nodes use to store signature shares they receive from other
// nodes (or generated themselves).
type SigShareDatabase = BTreeMap<Task, SigShareSet>;

// The database schema that validator nodes use to store signature shares they receive from other
// nodes (or generated themselves).
type SigDatabase = BTreeMap<Task, Signature>;

#[derive(Clone)]
struct SignedMsg {
    node_id: NodeId,
    task: Task,
    sig_share: SignatureShare,
}

#[derive(Clone)]
struct GotSignature {
    task: Task,
    sig: Signature,
}

#[derive(Message, Clone)]
#[rtype(result = "Option<NodeMessage>")]
enum NodeMessage {
    GotSignature(GotSignature),
    SignedMsg(SignedMsg),
    NewRequest(Payload),
}

struct NodeActor {
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    pending_task_db: SigShareDatabase,
    completed_task_db: SigDatabase,
}

impl Actor for NodeActor {
    type Context = Context<Self>;
}

impl NodeActor {
    fn handle_signed_msg(&mut self, msg: SignedMsg) -> Option<NodeMessage> {
        // TODO: run some check that the msg.task.payload makes sense, fail if not

        // You are too late, we have already completed the signature
        if self.completed_task_db.contains_key(&msg.task) {
            return None;
        }

        let sig_shares = self
            .pending_task_db
            .entry(msg.task.clone())
            .or_insert_with(|| BTreeMap::new());
        match sig_shares.entry(msg.node_id) {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(msg.sig_share);
                if let Ok(sig) = self.pk_set.combine_signatures(sig_shares.iter()) {
                    Some(NodeMessage::GotSignature(GotSignature {
                        task: msg.task,
                        sig,
                    }))
                } else {
                    Some(NodeMessage::SignedMsg(SignedMsg {
                        node_id: self.id,
                        sig_share: self.sk_share.sign(&msg.task.payload),
                        task: msg.task,
                    }))
                }
            }
            Entry::Occupied(occupied_entry) if occupied_entry.get() == &msg.sig_share => None,
            Entry::Occupied(_) => {
                println!("someone is lying to me :(");
                None
            }
        }
    }

    fn handle_got_signature(&mut self, msg: GotSignature) -> Option<NodeMessage> {
        if self.pk_set.public_key().verify(&msg.sig, &msg.task.payload) {
            self.pending_task_db.remove(&msg.task);
            self.completed_task_db.insert(msg.task, msg.sig);
            // TODO: if this is the node that is connected to the user, then respond
        }

        None
    }

    fn handle_new_request(&mut self, payload: Payload) -> Option<NodeMessage> {
        // TODO: run some check that the payload makes sense, fail if not

        let mut rng = rand::thread_rng();
        Some(NodeMessage::SignedMsg(SignedMsg {
            node_id: self.id,
            sig_share: self.sk_share.sign(&payload),
            task: Task {
                id: rng.next_u64(),
                payload,
            },
        }))
    }
}

impl Handler<NodeMessage> for NodeActor {
    type Result = Option<NodeMessage>;

    fn handle(&mut self, msg: NodeMessage, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            NodeMessage::GotSignature(msg) => self.handle_got_signature(msg),
            NodeMessage::SignedMsg(msg) => self.handle_signed_msg(msg),
            NodeMessage::NewRequest(payload) => self.handle_new_request(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::{NodeActor, NodeMessage};
    use actix::prelude::*;
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKeySet;

    #[actix_rt::test]
    async fn test_trio() -> anyhow::Result<()> {
        let sk_set = SecretKeySet::random(2, &mut rand::thread_rng());
        let pk_set = sk_set.public_keys();

        let nodes = (0..3)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                NodeActor {
                    id,
                    pk_set: pk_set.clone(),
                    sk_share,
                    pending_task_db: BTreeMap::new(),
                    completed_task_db: BTreeMap::new(),
                }
                .start()
            })
            .collect::<Vec<_>>();

        let payload = vec![1u8, 2, 3];

        let mut messages: Vec<NodeMessage> = Vec::new();
        // send initial signing request
        nodes[0]
            .send(NodeMessage::NewRequest(payload.clone()))
            .await?
            .into_iter()
            .for_each(|v| messages.push(v));

        while !messages.is_empty() {
            let msg = messages.pop().unwrap();

            // propagate message to all nodes (including yourself, whatever)
            for node in &nodes {
                node.send(msg.clone())
                    .await?
                    .into_iter()
                    .for_each(|v| messages.push(v));
            }

            if let NodeMessage::GotSignature(msg) = msg {
                println!("Got signature: {:?}", msg.sig);
                assert!(pk_set.public_key().verify(&msg.sig, &payload));
            }
        }

        // stop system and exit
        System::current().stop();

        Ok(())
    }
}
