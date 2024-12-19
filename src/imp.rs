/*
 * Copyright 2024 RingNet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{trace, warn};

use ringlink_identity::{DeviceID, Identity, PublicIdentity};
use ringlink_protocol::body::Binding;
use ringlink_transport::Transport;

use crate::agent::Agent;
use crate::candidate::{Candidate, LocalCandidates};
use crate::error::{Error, Result};
use crate::message::BindMessage;
use crate::server::ServerGather;

pub struct P2PManager<T> {
    identity: Identity,

    socket: T,

    local: LocalCandidates,

    server_gather: ServerGather<T>,

    agents: RwLock<HashMap<DeviceID, Arc<Agent<T>>>>,

    tasks: Vec<JoinHandle<()>>,
}

impl<T> P2PManager<T>
where
    T: Transport + Sync + Send + 'static,
{
    pub fn new(identity: Identity, socket: T) -> Result<P2PManager<T>> {
        let local_port = socket.local_port().unwrap_or(0);
        let local_gathers = crate::gather::get_local_candidate(local_port, 32);
        let local = LocalCandidates::from(local_gathers);

        let mut tasks = Vec::new();
        #[cfg(feature = "upnp")]
        {
            let id = format!("{}", identity.id());
            let local = local.clone();
            let handle = tokio::spawn(async move {
                let mut tk = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tk.tick().await;
                    match crate::gather::get_upnp_candidates(&id, local_port).await {
                        Ok(candidates) => {
                            for candidate in candidates {
                                local.insert(candidate);
                            }
                        }
                        Err(e) => {
                            warn!("get UPnP candidate failed: {}", e);
                        }
                    }
                }
            });
            tasks.push(handle);
        }

        let server_gather = ServerGather::new(identity.clone(), local.clone(), socket.clone()?)?;

        Ok(P2PManager {
            identity,
            socket,
            local,
            server_gather,
            agents: Default::default(),
            tasks,
        })
    }

    /// add a peer
    ///
    /// if peer already exist, try restart agent
    pub async fn add_peer(&self, identity: PublicIdentity) -> Arc<Agent<T>> {
        let id = identity.id();
        let mut agents = self.agents.write().await;
        match agents.get(&id) {
            Some(agent) => {
                agent.restart().await.ok();
                return agent.clone();
            }
            None => {
                let agent = Arc::new(Agent::new(
                    self.identity.clone(),
                    identity,
                    self.socket.clone().unwrap(),
                    self.local.clone(),
                ));

                agents.insert(id, agent.clone());
                return agent;
            }
        }
    }

    /// Remove a peer
    pub async fn remove_peer(&self, id: DeviceID) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.remove(&id) {
            agent.stop();
        }
    }

    /// update known peers
    ///
    /// * remove peer that not present in `peers`
    /// * add new peer in `peers`
    pub async fn set_peers(&self, peers: &HashSet<PublicIdentity>) {
        let mut agents = self.agents.write().await;
        let exists = agents.keys().copied().collect::<HashSet<_>>();
        let peers_ids = peers.iter().map(|it| it.id()).collect::<HashSet<_>>();

        for removed in exists.difference(&peers_ids) {
            let agent = agents.remove(removed);
            if let Some(agent) = agent {
                agent.stop();
            }
        }

        for new in peers_ids.difference(&exists) {
            let public_identity = peers.iter().find(|it| it.id() == *new).unwrap();
            let agent = Arc::new(Agent::new(
                self.identity.clone(),
                public_identity.clone(),
                self.socket.clone().unwrap(),
                self.local.clone(),
            ));

            agents.insert(*new, agent);
        }
    }

    /// return current gathered local candidates, include server-reflexive and peer-reflexive candidates
    pub async fn local_candidates(&self) -> Result<HashSet<Candidate>> {
        let local = self.local.get();

        Ok(local.iter().cloned().collect())
    }

    /// handle input binding data
    ///
    /// # Arguments
    /// * `binding` - binding data decoded from packet
    /// * `src` - source address of the packet
    pub async fn handle_input(&self, binding: Binding, src: SocketAddr) -> Result<()> {
        if binding.from == DeviceID::default() {
            // may from center server
            let message = BindMessage::decode(&*binding.body)?;

            self.server_gather.handle_input(message, src).await;
        } else {
            let mut sig_buff = BytesMut::with_capacity(binding.body.len() + size_of::<DeviceID>());
            sig_buff.put(&*binding.from);
            sig_buff.put(&*binding.body);

            let message = BindMessage::decode(&*binding.body)?;

            let agents = self.agents.read().await;
            match agents.get(&binding.from) {
                Some(agent) => {
                    let verified = agent.verify(&sig_buff, &binding.signature)?;
                    if !verified {
                        return Err(Error::InvalidSignature);
                    }
                    agent.handle_input(message, src).await?;
                }
                None => {
                    trace!("unknown peer {}, ignore", binding.from.to_string());
                }
            }
        }

        Ok(())
    }

    /// send data to a client
    ///
    /// # Returns
    /// return Ok indicates data is send
    pub async fn send_to(&self, to: DeviceID, data: Bytes) -> Result<()> {
        let agents = self.agents.read().await;
        match agents.get(&to) {
            Some(agent) => {
                agent.send(data).await?;

                Ok(())
            }
            None => {
                trace!("unknown peer {}, ignore", to.to_string());

                Err(Error::UnknownPeer)
            }
        }
    }
}

impl<T> P2PManager<T> {
    pub fn stop(&self) {
        self.server_gather.stop();
        for task in &self.tasks {
            task.abort();
        }

        tokio::task::block_in_place(|| {
            // fixme: will lock infinite
            let agents = self.agents.blocking_write();
            for (_, agent) in agents.iter() {
                agent.stop();
            }
        });
    }

    /// Restart all agents
    pub async fn restart_all(&self) {
        let agents = self.agents.write().await;
        for agent in agents.values() {
            let _ = agent.restart().await;
        }
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, id: DeviceID) -> bool {
        let agents = self.agents.read().await;
        match agents.get(&id) {
            None => false,
            Some(agent) => agent.address().is_some(),
        }
    }

    /// Set remote candidates for an agent
    ///
    /// Will remove exist candidate if the input argument doesn't contain that candidate.
    pub async fn set_remote_candidates(&self, id: DeviceID, candidates: Vec<Candidate>) {
        let agents = self.agents.read().await;
        match agents.get(&id) {
            Some(agent) => {
                agent
                    .set_remote_candidate(candidates.into_iter().collect())
                    .await;
            }
            None => {
                warn!("unknown peer {}, ignore", id.to_string());
            }
        }
    }
}
