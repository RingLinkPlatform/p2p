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

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use ringlink_identity::{DeviceID, Identity};
use ringlink_protocol::body::Binding;
use ringlink_protocol::{Packet, PacketBody, PacketMessage};
use ringlink_transport::Transport;

use crate::candidate::CandidateType;
use crate::candidate::{Candidate, LocalCandidates};
use crate::error::Result;
use crate::message::{BindBody, BindMessage, BindRequest};

const DEFAULT_SERVERS: &[&str] = &["stun1.service.ring.link:3479"];
const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(15);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(3);

struct Inner<T> {
    identity: Identity,
    /// shared local candidates
    local: LocalCandidates,
    /// socket used to send message
    socket: T,
    /// known ringlink stun server
    servers: Mutex<Vec<Server>>,
}

/// connect to ringlink stun and gather server-reflexive candidates
pub struct ServerGather<T> {
    inner: Arc<Inner<T>>,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug)]
struct Server {
    id: u64,
    addr: SocketAddr,
    trans: Transaction,
}

#[derive(Debug)]
struct Transaction {
    /// unique transaction id
    id: u64,
    /// next keep-alive send time
    next: Instant,
    /// the time when this transaction sent
    send_time: Instant,
    /// latest time receive response
    latest_recv: Option<Instant>,
}

impl Server {
    fn default() -> Result<Vec<Server>> {
        Self::parse(DEFAULT_SERVERS)
    }

    fn parse(servers: &[&str]) -> Result<Vec<Server>> {
        let mut ret = Vec::new();

        let now = Instant::now();
        let mut set = HashSet::new();
        for server_address in servers {
            for addr in server_address.to_socket_addrs()? {
                if set.contains(&addr) {
                    continue;
                }
                set.insert(addr);

                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);

                let s = Server {
                    id: hasher.finish(),
                    addr,
                    trans: Transaction {
                        id: rand::random(),
                        next: now,
                        send_time: now,
                        latest_recv: None,
                    },
                };

                ret.push(s);
            }
        }

        Ok(ret)
    }
}

impl<T> ServerGather<T>
where
    T: Transport + Sync + Send + 'static,
{
    pub fn new(identity: Identity, local: LocalCandidates, socket: T) -> Result<ServerGather<T>> {
        let servers = Server::default()?;

        let inner = Arc::new(Inner {
            identity,
            local,
            socket,
            servers: Mutex::new(servers),
        });
        let handle = {
            let inner = inner.clone();
            tokio::spawn(async move { inner.run().await })
        };

        Ok(ServerGather { inner, handle })
    }

    pub async fn handle_input(&self, message: BindMessage, src: SocketAddr) {
        match message.body {
            BindBody::Response(response) => {
                debug!(server=%src, "receive stun server response {}", response.mapped_address);

                let mut servers = self.inner.servers.lock().await;
                let s = servers
                    .iter_mut()
                    .enumerate()
                    .find(|(_, s)| s.trans.id == message.transaction_id);
                if let Some((_, s)) = s {
                    if s.addr != src {
                        warn!(
                            "receive a response from {}, but server address is {}",
                            src, s.addr
                        );

                        return;
                    }

                    let now = Instant::now();
                    s.trans.latest_recv = Some(now);

                    // update candidate info
                    let c = Candidate {
                        id: s.id,
                        typ: CandidateType::ServerReflexive,
                        address: response.mapped_address,
                        priority: 0,
                    };

                    if now.duration_since(s.trans.send_time) <= KEEP_ALIVE_TIMEOUT {
                        // add candidate
                        debug!("got server candidate: {}", c);
                        self.inner.local.insert(c);
                    } else {
                        warn!(
                            "server-reflexive candidate {} timeout",
                            response.mapped_address
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

impl<T> ServerGather<T> {
    pub fn stop(&self) {
        self.handle.abort();
    }
}

impl<T> Inner<T>
where
    T: Transport + Send + Sync + 'static,
{
    async fn run(&self) {
        debug!("server gather running");
        // init
        let mut servers = self.servers.lock().await;
        for s in servers.iter_mut() {
            s.trans.send_time = Instant::now();
            s.trans.next = s.trans.send_time + DEFAULT_KEEP_ALIVE;

            debug!(server=%s.addr, "send server bind");
            self.send(s).await.ok();
        }
        drop(servers);

        loop {
            let mut servers = self.servers.lock().await;

            for s in servers.iter_mut() {
                if s.trans.next <= Instant::now() {
                    // should send keep-alive message
                    // but first check timeout

                    match s
                        .trans
                        .latest_recv
                        .map(|it| it.duration_since(s.trans.send_time))
                    {
                        Some(dur) if dur <= KEEP_ALIVE_TIMEOUT => {
                            // no timeout, send next keep-alive

                            s.trans.send_time = Instant::now();
                            s.trans.next = s.trans.send_time + DEFAULT_KEEP_ALIVE;
                            s.trans.latest_recv = None;

                            self.send(s).await.ok();
                        }
                        _ => {
                            // timeout
                            self.local.mut_on(|local| {
                                // remove candidate obtained from this server
                                local.retain(|c| c.candidate.id != s.id);
                            });

                            // but still send keep-alive
                            s.trans.send_time = Instant::now();
                            s.trans.next = s.trans.send_time + DEFAULT_KEEP_ALIVE;
                            s.trans.latest_recv = None;

                            self.send(s).await.ok();
                        }
                    }
                }
            }

            let min_wait = servers.iter().map(|s| s.trans.next).min().unwrap(); // server cannot be empty
            let min_wait = min_wait.duration_since(Instant::now());

            drop(servers);
            tokio::time::sleep(min_wait).await;
        }
    }

    async fn send(&self, server: &Server) -> Result<usize> {
        let message = BindMessage {
            transaction_id: server.trans.id,
            body: BindBody::Request(BindRequest {
                priority: 0,
                use_candidate: false,
                controlling: None,
                controlled: None,
            }),
        };

        let mut buf = Vec::new();
        message.encode(&mut buf)?;

        // make signature for message body
        let mut sig_buff = BytesMut::with_capacity(buf.len() + size_of::<DeviceID>());
        sig_buff.put(&*self.identity.id());
        sig_buff.put(&*buf);

        let signature = self.identity.sign(&sig_buff)?;

        let packet = Packet::new(
            self.identity.id(),
            DeviceID::default(),
            PacketBody::P2P(Binding {
                from: self.identity.id(),
                body: buf.into(),
                signature: Bytes::from(signature),
            }),
        );

        let mut buf = Vec::<u8>::new();
        packet.encode(&mut buf);

        self.socket
            .send(&buf, server.addr)
            .await
            .map_err(Into::into)
    }
}
