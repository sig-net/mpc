use futures::prelude::*;
use futures::stream::FuturesUnordered;
use ractor::{
    concurrency::Duration, Actor, ActorProcessingErr, ActorRef, BytesConvertable, RpcReplyPort,
};
use ractor_cluster::RactorClusterMessage;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

use crate::ouath::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::NodeId;

const MPC_RECOVERY_GROUP: &str = "mpc-recovery";

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
    type Msg = NodeMessage;
    type State = NodeActorState;
    type Arguments = (NodeId, PublicKeySet, SecretKeyShare);

    #[tracing::instrument(level = "debug", skip_all, fields(id = args.0))]
    async fn pre_start(
        &self,
        myself: ActorRef<Self>,
        args: (NodeId, PublicKeySet, SecretKeyShare),
    ) -> Result<Self::State, ActorProcessingErr> {
        tracing::debug!(group = MPC_RECOVERY_GROUP, "joining");
        ractor::pg::join(MPC_RECOVERY_GROUP.to_string(), vec![myself.get_cell()]);
        // create the initial state
        Ok(NodeActorState {
            id: args.0,
            pk_set: args.1,
            sk_share: args.2,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, fields(id = state.id, message))]
    async fn handle(
        &self,
        _myself: ActorRef<Self>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let remote_actors = ractor::pg::get_members(&MPC_RECOVERY_GROUP.to_string())
            .into_iter()
            .filter(|actor| !actor.get_id().is_local())
            .map(ActorRef::<Self>::from)
            .collect::<Vec<_>>();
        tracing::debug!(
            remote_actors = ?remote_actors.iter().map(|a| a.get_id()).collect::<Vec<_>>(),
            "connected to"
        );

        match message {
            NodeMessage::NewRequest(payload, reply) => {
                tracing::debug!(?payload, "new request");
                state
                    .handle_new_request(payload, reply, &remote_actors)
                    .await
            }
            NodeMessage::SignRequest(payload, reply) => {
                tracing::debug!(?payload, "sign request");
                state.handle_signed_msg(payload, reply).await
            }
        };
        Ok(())
    }
}

impl NodeActorState {
    fn sign(&self, payload: &[u8]) -> SignResponse {
        SignResponse {
            node_id: self.id,
            sig_share: self.sk_share.sign(payload),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn handle_signed_msg(&mut self, payload: Payload, reply: RpcReplyPort<SignResponse>) {
        // TODO: extract access token from payload
        let access_token = "validToken";
        let access_token_verifier = UniversalTokenVerifier {};
        match access_token_verifier.verify_token(access_token).await {
            Some(client_id) => {
                tracing::debug!("approved, cleintId: {}", client_id);

                let response = self.sign(&payload);
                tracing::debug!(?response, "replying");

                match reply.send(response) {
                    Ok(()) => {}
                    Err(e) => tracing::error!("failed to respond: {}", e),
                };
            }
            None => {
                tracing::error!("failed to verify access token");
            }
        }
    }

    async fn handle_new_request(
        &mut self,
        payload: Payload,
        reply: RpcReplyPort<SignatureResponse>,
        remote_actors: &Vec<ActorRef<NodeActor>>,
    ) {
        // TODO: extract access token from payload
        let access_token = "validToken";
        let access_token_verifier = UniversalTokenVerifier {};
        match access_token_verifier.verify_token(access_token).await {
            Some(client_id) => {
                tracing::debug!("approved, cleintId: {}", client_id);
                let mut futures = Vec::new();
                for actor in remote_actors {
                    tracing::debug!(actor = ?actor.get_id(), "asking actor");
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

                let mut responses = futures
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .filter_map(|r| r.ok())
                    .collect::<Vec<_>>();

                let response = self.sign(&payload);
                tracing::debug!(?response, "adding response from self");
                responses.push(response);

                tracing::debug!(
                    ?responses,
                    "got {} successful responses total",
                    responses.len()
                );

                let mut sig_shares = Vec::new();
                for sign_response in &responses {
                    if self
                        .pk_set
                        .public_key_share(sign_response.node_id)
                        .verify(&sign_response.sig_share, &payload)
                    {
                        sig_shares.push((sign_response.node_id, &sign_response.sig_share));
                    } else {
                        tracing::error!(?sign_response, "received invalid signature",);
                    }
                }

                tracing::debug!(
                    ?sig_shares,
                    "got {} valid signature shares total",
                    sig_shares.len()
                );

                if let Ok(sig) = self
                    .pk_set
                    .combine_signatures(sig_shares.clone().into_iter())
                {
                    tracing::debug!(?sig, "replying with full signature");
                    reply.send(SignatureResponse { sig }).unwrap();
                } else {
                    tracing::error!(
                        "expected to get at least {} shares, but only got {}",
                        self.pk_set.threshold() + 1,
                        sig_shares.len()
                    );
                }
            }
            None => {
                tracing::error!("failed to verify access token");
            }
        }
    }
}
