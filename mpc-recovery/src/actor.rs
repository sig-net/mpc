use futures::prelude::*;
use futures::stream::FuturesUnordered;
use ractor::{
    concurrency::Duration, Actor, ActorProcessingErr, ActorRef, BytesConvertable, RpcReplyPort,
};
use ractor_cluster::RactorClusterMessage;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

const MPC_RECOVERY_GROUP: &str = "mpc-recovery";

type NodeId = u64;
type Payload = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    node_id: NodeId,
    sig_share: SignatureShare,
}

impl BytesConvertable for SignResponse {
    fn into_bytes(self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub sig: Signature,
}

impl BytesConvertable for SignatureResponse {
    fn into_bytes(self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[derive(RactorClusterMessage, Debug)]
pub enum NodeMessage {
    #[rpc]
    NewRequest(Payload, RpcReplyPort<SignatureResponse>),
    #[rpc]
    SignRequest(Payload, RpcReplyPort<SignResponse>),
}

pub struct NodeActor;

pub struct NodeActorState {
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
}

#[async_trait::async_trait]
impl Actor for NodeActor {
    // An actor has a message type
    type Msg = NodeMessage;
    // and (optionally) internal state
    type State = NodeActorState;
    // Startup initialization args
    type Arguments = (NodeId, PublicKeySet, SecretKeyShare);

    async fn pre_start(
        &self,
        myself: ActorRef<Self>,
        args: (NodeId, PublicKeySet, SecretKeyShare),
    ) -> Result<Self::State, ActorProcessingErr> {
        ractor::pg::join(MPC_RECOVERY_GROUP.to_string(), vec![myself.get_cell()]);
        // create the initial state
        Ok(NodeActorState {
            id: args.0,
            pk_set: args.1,
            sk_share: args.2,
        })
    }

    // This is our main message handler
    async fn handle(
        &self,
        _myself: ActorRef<Self>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        for actor in ractor::pg::get_members(&MPC_RECOVERY_GROUP.to_string()) {
            let actor_ref = ActorRef::<Self>::from(actor);
            println!(
                "Has an actor {:?} {:?} {:?}",
                actor_ref.get_id(),
                actor_ref.get_name(),
                actor_ref.get_cell()
            )
        }
        let remote_actors = ractor::pg::get_members(&MPC_RECOVERY_GROUP.to_string())
            .into_iter()
            .filter(|actor| !actor.get_id().is_local())
            .map(ActorRef::<Self>::from)
            .collect::<Vec<_>>();

        match message {
            NodeMessage::NewRequest(payload, reply) => {
                state
                    .handle_new_request(payload, reply, &remote_actors)
                    .await
            }
            NodeMessage::SignRequest(payload, reply) => state.handle_signed_msg(payload, reply),
        };
        Ok(())
    }
}

impl NodeActorState {
    fn handle_signed_msg(&mut self, payload: Payload, reply: RpcReplyPort<SignResponse>) {
        // TODO: run some check that the msg.task.payload makes sense, fail if not

        println!("Got a sign request");

        reply
            .send(SignResponse {
                node_id: self.id,
                sig_share: self.sk_share.sign(payload),
            })
            .unwrap();
    }

    async fn handle_new_request(
        &mut self,
        payload: Payload,
        reply: RpcReplyPort<SignatureResponse>,
        remote_actors: &Vec<ActorRef<NodeActor>>,
    ) {
        // TODO: run some check that the payload makes sense, fail if not

        let mut futures = Vec::new();
        println!("Asking {} nodes", remote_actors.len());
        for actor in remote_actors {
            let future = actor
                .call(
                    |tx| NodeMessage::SignRequest(payload.clone(), tx),
                    Some(Duration::from_millis(2000)),
                )
                .map(|r| r.map_err(ractor::RactorErr::from))
                .map(|r| match r {
                    Ok(ractor::rpc::CallResult::Success(ok_value)) => Ok(ok_value),
                    Ok(cr) => Err(ractor::RactorErr::from(cr)),
                    Err(e) => Err(e),
                });
            futures.push(future);
        }

        // create unordered collection of futures
        let futures = futures.into_iter().collect::<FuturesUnordered<_>>();

        // use collection as a stream, await only first *threshold* futures to complete
        let mut first_t = futures
            .take(self.pk_set.threshold())
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();

        first_t.push(SignResponse {
            node_id: self.id,
            sig_share: self.sk_share.sign(&payload),
        });

        let mut sig_shares = Vec::new();
        for sign_response in &first_t {
            if self
                .pk_set
                .public_key_share(sign_response.node_id)
                .verify(&sign_response.sig_share, &payload)
            {
                sig_shares.push((sign_response.node_id, &sign_response.sig_share));
            } else {
                println!(
                    "Node {} sent me an invalid signature >:(",
                    sign_response.node_id
                )
            }
        }

        if let Ok(sig) = self
            .pk_set
            .combine_signatures(sig_shares.clone().into_iter())
        {
            println!("Got full signature: {:?}", sig);
            reply.send(SignatureResponse { sig }).unwrap();
        } else {
            println!(
                "Expected to get {} shares, but only got {}",
                self.pk_set.threshold() + 1,
                sig_shares.len()
            );
        }
    }
}
