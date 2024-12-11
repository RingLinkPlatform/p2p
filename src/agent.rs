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

//! implementation of p2p agent
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    Mutex, Notify, RwLock,
};
use tracing::{debug, instrument, trace, warn};

use crate::candidate::{
    compute_priority, Candidate, CandidatePair, CandidateType, LocalCandidates, PairState,
};
use crate::error::Error;
use crate::error::Result;
use crate::message::BindMessage;
use crate::message::{BindBody, BindRequest, BindResponse};
use ringlink_identity::{DeviceID, Identity, PublicIdentity};
use ringlink_protocol::body::Binding;
use ringlink_protocol::{Packet, PacketBody, PacketMessage};
use ringlink_transport::Transport;

const ROLE_CONTROLLING: u8 = 0;
const ROLE_CONTROLLED: u8 = 1;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_RETRY: u8 = 5;
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(15);
const MIN_KEEP_ALIVE_CHECK_INTERVAL: u64 = 4000;
const MAX_KEEP_ALIVE_CHECK_INTERVAL: u64 = 6000;

/// state of agent
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AgentState {
    /// agent failed to find a valid pair
    ///
    /// all pair checked, and no pair can establish peer-to-peer connection.
    Failed = 1,
    /// agent successfully establish a peer-to-peer connection.
    ///
    /// caller should do keep-alive when connected
    Connected = 2,
    /// some connectivity check are running, agent may or may not connected.
    Running = 3,
}

impl From<u8> for AgentState {
    fn from(v: u8) -> Self {
        match v {
            1 => AgentState::Failed,
            2 => AgentState::Connected,
            3 => AgentState::Running,
            _ => unreachable!(),
        }
    }
}

struct AgentInner<T> {
    /// agent use identity to sign message
    identity: Identity,
    /// peer public identity
    public_identity: PublicIdentity,
    /// local candidates
    local: LocalCandidates,
    /// known remote candidates
    remotes: RwLock<HashSet<Candidate>>,
    /// similar to ICE agent role
    role: AtomicU8,
    /// random value used to resolve role conflict
    tiebreaker: AtomicU64,
    /// current state
    state: AtomicU8,
    /// socket used to send agent message and data
    socket: T,
    /// selected and success candidate
    selected: ArcSwapOption<SocketAddr>,
    /// latency of selected candidate
    latency: AtomicU32,
    /// connectivity check and associated candidate pair
    ///
    /// **sorted by pair priority**
    checks: Mutex<Vec<CheckPair>>,
    /// task notify
    notify: Arc<Notify>,
    /// send agent state change event
    event: Sender<AgentState>,
}

/// agent for establish peer-to-peer connection.
///
/// similar to ICE agent
pub struct Agent<T> {
    inner: Arc<AgentInner<T>>,
    /// join handle of background task.
    handle: tokio::task::JoinHandle<()>,
    notify: Arc<Notify>,
}

struct CheckPair {
    /// associated candidate pair
    pair: CandidatePair,
    /// transaction of this pair
    trans: Transaction,
    /// latency of last transaction
    latency: u32,
}

impl CheckPair {
    fn failed(&mut self) {
        self.pair.failed();
        self.trans.failed();
    }
}

#[derive(Clone)]
struct Transaction {
    /// unique transaction id
    id: u64,
    /// time that last send
    last_send: Instant,
    /// time that should send
    next_send: Instant,
    /// remains retry count
    retry: u8,
    /// timeout for retransmission
    retry_timeout: Duration,
    /// the agent role when we sent
    role: u8,
    /// should this transaction run keep-alive
    keep_alive: bool,
    /// when keep-alive expired
    keep_alive_expired: Instant,
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let next_send = self.next_send.duration_since(Instant::now());

        write!(
            f,
            "{}/{DEFAULT_RETRY} {{{:?}, {:?}}}",
            self.retry, next_send, self.retry_timeout
        )?;

        if self.keep_alive {
            write!(f, "[x]")?;
        } else {
            write!(f, "[ ]")?;
        }

        Ok(())
    }
}

impl Transaction {
    fn init() -> Transaction {
        let now = Instant::now();
        Transaction {
            id: 0,
            last_send: now,
            next_send: now,
            retry: DEFAULT_RETRY,
            retry_timeout: DEFAULT_TIMEOUT,
            role: 0,
            keep_alive: false,
            keep_alive_expired: now,
        }
    }

    fn failed(&mut self) {
        self.retry = 0;
        self.keep_alive = false;
    }
}

impl<T> Agent<T>
where
    T: Transport + Sync + Send + 'static,
{
    pub fn new(
        identity: Identity,
        public_identity: PublicIdentity,
        socket: T,
        local: LocalCandidates,
    ) -> Agent<T> {
        let notify = Arc::new(Notify::new());
        let (event, _) = broadcast::channel(8);

        let inner = Arc::new(AgentInner {
            identity,
            public_identity,
            local,
            remotes: Default::default(),
            role: AtomicU8::new(ROLE_CONTROLLING),
            tiebreaker: AtomicU64::new(rand::random()),
            state: AtomicU8::new(AgentState::Running as u8),
            socket,
            selected: Default::default(),
            latency: AtomicU32::new(u32::MAX),
            checks: Default::default(),
            notify: notify.clone(),
            event,
        });

        let handle = {
            let inner = inner.clone();
            tokio::spawn(async move { inner.task().await })
        };

        Agent {
            inner,
            handle,
            notify,
        }
    }

    pub async fn handle_input(&self, message: BindMessage, src: SocketAddr) -> Result<()> {
        match message.body {
            BindBody::Request(request) => {
                self.inner
                    .add_remote_reflexive_candidate(
                        CandidateType::PeerReflexive,
                        request.priority,
                        src,
                    )
                    .await;

                self.inner
                    .handle_request(message.transaction_id, request, src)
                    .await?;
            }
            BindBody::Response(response) => {
                self.inner
                    .add_remote_reflexive_candidate(CandidateType::PeerReflexive, 0, src)
                    .await;

                self.inner
                    .handle_response(message.transaction_id, response, src)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn send_slice(&self, data: &[u8]) -> Result<usize> {
        let selected = self.inner.selected.load();
        if let Some(selected) = &*selected {
            self.inner
                .socket
                .send(data, **selected)
                .await
                .map_err(Into::into)
        } else {
            Err(Error::Disconnected)
        }
    }

    pub async fn send(&self, data: Bytes) -> Result<usize> {
        let selected = self.inner.selected.load();
        if let Some(selected) = &*selected {
            self.inner
                .socket
                .send(&data, **selected)
                .await
                .map_err(Into::into)
        } else {
            Err(Error::Disconnected)
        }
    }
}

impl<T> Agent<T> {
    pub async fn restart(&self) -> Result<()> {
        debug!("{} restart agent", self.inner.public_identity.id());
        // reset all pair state
        let mut checks = self.inner.checks.lock().await;
        for c in checks.iter_mut() {
            c.pair.state = PairState::Waiting;
            c.pair.nominated = false;
            enqueue_transaction(c, Duration::default());
        }

        // set state to running
        self.inner.set_state(AgentState::Running);

        // unpark background task
        self.notify.notify_one();

        Ok(())
    }

    #[instrument(name = "set-remote", skip_all, fields(id = %self.inner.public_identity.id()))]
    pub async fn set_remote_candidate(&self, candidates: HashSet<Candidate>) {
        // don't reorder the lock order, or may deadlock
        let mut remotes = self.inner.remotes.write().await;

        let mut new_remotes = remotes.clone();
        new_remotes.extend(candidates.clone());

        if !remotes.eq(&new_remotes) {
            debug!("candidate changes, restart",);

            let mut checks = self.inner.checks.lock().await;
            checks.clear();

            for candidate in &new_remotes {
                let pair = CandidatePair::new(None, candidate.clone(), self.inner.is_controlling());
                let mut check = CheckPair {
                    pair,
                    trans: Transaction::init(),
                    latency: u32::MAX,
                };

                check.trans.id = rand::random();
                check.pair.state = PairState::Waiting;
                enqueue_transaction(&mut check, Duration::default());

                checks.push(check);
            }

            // because we hold the mutex lock, no one can access checks, it is safe to sort finally.
            checks.sort_by_key(|c| c.pair.priority);
            let _ = std::mem::replace(&mut *remotes, candidates);

            if self.inner.state() == AgentState::Failed {
                self.inner.set_state(AgentState::Running);
            }

            self.notify.notify_one();
        } else {
            debug!("remote candidates not changed, ignore");
            if self.inner.state() == AgentState::Failed {
                debug!("agent failed, restart");
                let _ = self.restart().await;
            }
        }
    }

    pub fn stop(&self) {
        self.handle.abort();
        self.inner.set_state(AgentState::Failed);
    }

    pub fn state(&self) -> AgentState {
        self.inner.state()
    }

    pub fn subscribe_state(&self) -> Receiver<AgentState> {
        self.inner.event.subscribe()
    }

    pub fn address(&self) -> Option<SocketAddr> {
        self.inner.selected.load().as_deref().copied()
    }

    pub fn latency(&self) -> u32 {
        self.inner.latency.load(Ordering::Relaxed)
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.inner.selected.load().as_deref().copied()
    }
}

impl<T> AgentInner<T>
where
    T: Transport + Send + 'static,
{
    #[instrument(fields(id = %self.public_identity.id()), skip(self))]
    async fn task(&self) {
        loop {
            debug!("agent task ticking");
            let mut checks = self.checks.lock().await;
            // 1. check if there is some transaction should be resent.
            //    also check keep-alive
            for c in checks.iter_mut() {
                let now = Instant::now();
                let CheckPair { pair, trans, .. } = c;

                debug!("checking: {}, trans: {}", pair, trans);

                match pair.state {
                    PairState::Waiting | PairState::InProgress => {
                        if trans.next_send > now {
                            continue;
                        }

                        if trans.retry > 0 {
                            trace!(
                                "send retry request to {}, retry remains: {}",
                                pair.remote.address,
                                trans.retry
                            );
                            pair.state = PairState::InProgress;
                            trans.retry -= 1;
                            trans.last_send = now;
                            trans.next_send = now + trans.retry_timeout;
                            trans.retry_timeout *= 2;
                            trans.role = self.role.load(Ordering::Relaxed);

                            if let Err(e) = self
                                .send_request(
                                    c,
                                    self.is_controlling() && c.pair.nomination_requested,
                                )
                                .await
                            {
                                warn!("send request to {} failed: {}", c.pair.remote.address, e);
                                c.failed();
                            }
                        } else {
                            debug!("no retry remains, pair failed");
                            c.failed();
                        }
                    }
                    PairState::Succeed => {
                        trace!(
                            "keep-alive expired in: {:?}",
                            trans.keep_alive_expired.duration_since(now)
                        );
                        if trans.keep_alive_expired < now {
                            // keep-alive expired
                            warn!("pair keep-alive expired");
                            c.failed();
                            continue;
                        }

                        // send keep-alive
                        if trans.keep_alive && trans.next_send <= now {
                            trace!("send keep-alive");
                            trans.id = rand::random();
                            trans.last_send = now;
                            trans.role = self.role.load(Ordering::Relaxed);

                            if let Err(e) = self
                                .send_request(
                                    c,
                                    self.is_controlling() && c.pair.nomination_requested,
                                )
                                .await
                            {
                                warn!("send keep-alive to {} failed: {}", c.pair.remote.address, e);
                            }
                            // random from 4 to 6 secs
                            let dur = MIN_KEEP_ALIVE_CHECK_INTERVAL
                                + rand::random::<u64>()
                                    % (MAX_KEEP_ALIVE_CHECK_INTERVAL
                                        - MIN_KEEP_ALIVE_CHECK_INTERVAL
                                        + 1);
                            enqueue_transaction(c, Duration::from_millis(dur));
                        }
                    }
                    _ => {}
                }
            }

            // 2. if there is a succeed pair, nominate it.
            //    or if already nominated, change agent state to CONNECTED.
            let mut nominated = None;
            let mut latency = u32::MAX;
            for idx in 0..checks.len() {
                let now = Instant::now();
                let c = &mut checks[idx];

                // if there is a nominated pair
                if c.pair.nominated {
                    if c.pair.state != PairState::Succeed {
                        warn!("pair {} nominated, but pair not ready", c.pair.remote);
                        continue;
                    }

                    // checks are sorted by priority
                    match nominated {
                        Some(_) => {}
                        None => {
                            nominated = Some(c.pair.remote.address);
                            latency = c.latency;
                        }
                    }

                    c.trans.keep_alive = true;
                } else if c.pair.state == PairState::Succeed {
                    // nominate this pair
                    if self.is_controlling() && !c.pair.nomination_requested {
                        trace!("send nominate request to {}", c.pair);
                        c.pair.nomination_requested = true;
                        // set pair state to InProgress to enable retry
                        c.pair.state = PairState::InProgress;
                        c.trans.keep_alive = false;
                        c.trans.last_send = now;
                        c.trans.role = self.role.load(Ordering::Relaxed);
                        c.trans.next_send = now + DEFAULT_TIMEOUT;
                        c.trans.retry_timeout = DEFAULT_TIMEOUT;
                        c.trans.retry = DEFAULT_RETRY;

                        if let Err(e) = self.send_request(c, true).await {
                            warn!(
                                "send nominate request to {} failed: {}",
                                c.pair.remote.address, e
                            );
                            c.failed();
                        }
                    }
                }
            }

            // if we have nominated pair, set agent state to connected
            if let Some(nominated) = nominated {
                if self.state() != AgentState::Connected {
                    self.set_state(AgentState::Connected);
                }

                match self.selected.load().as_ref().map(|it| **it) {
                    None => {
                        debug!("agent connected, remote: {}", nominated);
                        self.selected.store(Some(Arc::new(nominated)));
                        self.latency.store(latency, Ordering::Relaxed);
                    }
                    Some(current) => {
                        if current != nominated {
                            debug!("new selected pair: {}", nominated);
                            self.selected.store(Some(Arc::new(nominated)));
                        }
                        self.latency.store(latency, Ordering::Relaxed);
                    }
                }
            }

            // find minimal next_send
            // 1. pair in Waiting or InProgress
            //    check has not been sent,
            //    or check should schedule a retry,
            //    current nominating pair are in InProgress state
            // 2. pair enable keep-alive
            let min_wait = checks
                .iter()
                .filter(|c| {
                    matches!(c.pair.state, PairState::Waiting | PairState::InProgress)
                        || c.trans.keep_alive
                })
                .map(|c| (c.pair.clone(), c.trans.clone()))
                .min_by_key(|it| it.1.next_send);
            drop(checks);

            match min_wait {
                None => {
                    debug!("no pair to check, agent failed");
                    // if min return None, there is no keep-alive transaction and
                    // all pair is in Failed or Frozen
                    self.selected.store(None);
                    self.latency.store(u32::MAX, Ordering::Relaxed);
                    self.set_state(AgentState::Failed);

                    self.notify.notified().await;
                }
                Some((pair, trans)) => {
                    let dur = trans.next_send.checked_duration_since(Instant::now());
                    if let Some(dur) = dur {
                        debug!("park task, next check in {:?}, pair: {}", dur, pair);
                        tokio::time::sleep(dur).await;
                    }
                    // else, a retry or keep-alive already happened
                }
            }
        }
    }

    fn prepare_request(&self, pair: &CandidatePair, nominate: bool) -> BindMessage {
        let priority = match &pair.local {
            Some(local) => {
                (local.priority & 0xffffff) | (CandidateType::PeerReflexive.type_preference() << 24)
            }
            None => compute_priority(
                CandidateType::PeerReflexive,
                pair.remote.address.is_ipv4(),
                0,
            ),
        };

        let tiebreaker = self.tiebreaker.load(Ordering::Acquire);

        BindMessage::request(BindRequest {
            priority,
            use_candidate: nominate,
            controlling: if self.is_controlling() {
                Some(tiebreaker)
            } else {
                None
            },
            controlled: if !self.is_controlling() {
                Some(tiebreaker)
            } else {
                None
            },
        })
    }

    fn prepare_body(&self, message: BindMessage) -> Result<Binding> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;

        let mut sig_buff = BytesMut::with_capacity(buf.len() + size_of::<DeviceID>());
        sig_buff.put(&*self.identity.id());
        sig_buff.put(&*buf);

        let signature = self.identity.sign(&sig_buff)?;

        Ok(Binding {
            from: self.identity.id(),
            body: buf.into(),
            signature: Bytes::from(signature),
        })
    }

    async fn send_request(&self, check: &CheckPair, use_candidate: bool) -> Result<()> {
        let CheckPair { pair, trans, .. } = check;
        let mut request = self.prepare_request(pair, use_candidate);
        request.transaction_id = trans.id;

        let body = self.prepare_body(request)?;
        let packet = Packet::new(
            self.identity.id(),
            self.public_identity.id(),
            PacketBody::P2P(body),
        );
        let mut buf = BytesMut::with_capacity(4096);
        packet.encode(&mut buf);
        let buf = buf.freeze();

        trace!("send request({}) to {}", trans.id, pair);
        self.socket.send(&buf, pair.remote.address).await?;

        Ok(())
    }

    async fn fix_pairs(&self) {
        let mut checks = self.checks.lock().await;
        let role = self.is_controlling();

        for c in checks.iter_mut() {
            c.pair.set_role(role);
        }
    }
}

impl<T> AgentInner<T>
where
    T: Transport + Sync + Send + 'static,
{
    async fn reply(&self, transaction_id: u64, error: u32, src: SocketAddr) -> Result<usize> {
        let response = BindResponse {
            error,
            mapped_address: src,
        };
        let message = BindMessage::response(transaction_id, response);

        let body = self.prepare_body(message)?;
        let packet = Packet::new(
            self.identity.id(),
            self.public_identity.id(),
            PacketBody::P2P(body),
        );

        let mut buf = BytesMut::new();
        packet.encode(&mut buf);

        trace!("sending reply({}) to {}", transaction_id, src);

        self.socket.send(&buf, src).await.map_err(Into::into)
    }

    #[instrument(name = "request", skip(self, request), fields(id = %self.public_identity.id()))]
    async fn handle_request(
        &self,
        transaction_id: u64,
        request: BindRequest,
        src: SocketAddr,
    ) -> Result<()> {
        // RFC8445 7.3.1.1. resolve role conflict
        if self.is_controlling() {
            match request.controlling {
                Some(tiebreaker) => {
                    warn!("role conflict detected, both CONTROLLING");

                    if self.tiebreaker.load(Ordering::Acquire) >= tiebreaker {
                        trace!("ask peer to switch role");
                        self.reply(transaction_id, 487, src).await?;
                    } else {
                        trace!("switch role to CONTROLLED");
                        self.role.store(ROLE_CONTROLLED, Ordering::Release);
                        self.fix_pairs().await;
                    }

                    return Ok(());
                }
                None => {}
            }
        } else {
            if let Some(tiebreaker) = request.controlled {
                warn!("role conflict detected, both CONTROLLED");

                if self.tiebreaker.load(Ordering::Acquire) >= tiebreaker {
                    trace!("switch role to CONTROLLING");
                    self.role.store(ROLE_CONTROLLING, Ordering::Release);
                    self.fix_pairs().await;
                } else {
                    trace!("ask peer to switch role");
                    self.reply(transaction_id, 487, src).await?;
                }

                return Ok(());
            }
        }

        // find pair
        let mut checks = self.checks.lock().await;
        let pair = checks.iter_mut().find(|it| it.pair.remote.address == src);
        let check = match pair {
            Some(check) => check,
            None => {
                debug!("pair not found for remote: {}, ignore", src);
                return Ok(());
            }
        };

        if request.use_candidate {
            if request.controlling.is_none() {
                warn!("use-candidate request without controlling, ignore");
                return Ok(());
            }

            // RFC 8445 7.3.1.5. Updating the Nominated Flag:
            if check.pair.state == PairState::Succeed {
                debug!("pair succeed, nominate {}", check.pair.remote.address);
                check.pair.nominated = true;
            } else if !check.pair.nomination_requested {
                trace!(pair=%check.pair, "set nomination_requested flag");
                check.pair.nomination_requested = true;
            }
        }

        // response
        self.reply(transaction_id, 0, src).await?;

        // Triggered check
        if check.pair.state != PairState::Succeed {
            check.pair.state = PairState::Waiting;
            trace!("triggered check, pair: {:?}", check.pair);
            enqueue_transaction(check, Duration::from_millis(50));
            self.notify.notify_one();
        }

        Ok(())
    }

    #[instrument(name = "response", skip(self, response), fields(id = %self.public_identity.id()))]
    async fn handle_response(
        &self,
        transaction_id: u64,
        response: BindResponse,
        src: SocketAddr,
    ) -> Result<()> {
        let mut checks = self.checks.lock().await;
        let c = checks.iter_mut().find(|c| c.trans.id == transaction_id);
        if let Some(c) = c {
            if response.error == 487 {
                // role conflict
                warn!("role conflict detected");
                // if we send ICE-CONTROLLING, then change role to CONTROLLED
                // else, change role to CONTROLLING
                if c.trans.role == ROLE_CONTROLLING {
                    trace!("switch to CONTROLLED");
                    self.role.store(ROLE_CONTROLLED, Ordering::Release);
                } else {
                    trace!("switch to CONTROLLING");
                    self.role.store(ROLE_CONTROLLING, Ordering::Release);
                }

                // set a new tiebreaker
                let tiebreaker = rand::random();
                self.tiebreaker.store(tiebreaker, Ordering::Release);

                // retry this check
                enqueue_transaction(c, Duration::default());

                // fix pair priority
                drop(checks); // must drop this MutexGuard before call to fix_pairs()
                self.fix_pairs().await;

                return Ok(());
            }

            // for other error, set pair to Failed.
            if response.error != 0 {
                warn!("receive a error response");

                c.failed();

                return Ok(());
            }

            // Non-Symmetric Transport Addresses
            if c.pair.remote.address != src {
                warn!("non-symmetric transport addresses detected");

                c.failed();

                return Ok(());
            }

            // if pair already failed or frozen, but we receive a response
            if matches!(c.pair.state, PairState::Failed | PairState::Frozen) {
                warn!("receive a outdated response");
                return Ok(());
            }

            // learn peer-reflexive candidate
            let exist = self.local.exist_for_address(response.mapped_address);
            if !exist {
                debug!(
                    "adding a new peer-reflexive candidate {}",
                    response.mapped_address
                );

                // new peer-reflexive candidate
                let candidate = Candidate {
                    id: 0,
                    priority: 0,
                    typ: CandidateType::PeerReflexive,
                    address: response.mapped_address,
                };

                self.local.insert(candidate);
            }

            let local = self
                .local
                .find(|candidate| candidate.address == response.mapped_address);

            let current_state = c.pair.state;
            c.pair.local = local;
            c.pair.state = PairState::Succeed;
            c.trans.keep_alive = true;
            c.trans.keep_alive_expired = Instant::now() + KEEP_ALIVE_TIMEOUT;
            if current_state != PairState::Succeed {
                // triggered check
                enqueue_transaction(c, DEFAULT_TIMEOUT);
            }

            let latency = Instant::now().duration_since(c.trans.last_send).as_millis() as u32;
            c.latency = latency;

            if c.pair.nomination_requested {
                debug!("nominate pair {}", c.pair.remote.address);
                c.pair.nominated = true;
            }
        } else {
            warn!("transaction {} not found, ignore", transaction_id);
        }

        Ok(())
    }
}

impl<T> AgentInner<T> {
    /// return true if agent role is CONTROLLING
    fn is_controlling(&self) -> bool {
        self.role.load(Ordering::Acquire) == ROLE_CONTROLLING
    }

    fn state(&self) -> AgentState {
        self.state.load(Ordering::Acquire).into()
    }

    fn set_state(&self, state: AgentState) {
        self.state.store(state as u8, Ordering::Release);
        let _ = self.event.send(state);
    }

    async fn add_remote_reflexive_candidate(
        &self,
        typ: CandidateType,
        priority: u32,
        src: SocketAddr,
    ) {
        let mut remotes = self.remotes.write().await;
        if remotes
            .iter()
            .find(|it| it.typ == typ && it.address == src)
            .is_some()
        {
            return;
        }

        let mut candidate = Candidate {
            id: 0,
            typ,
            priority,
            address: src,
        };

        trace!("add remote reflexive candidate: {}", candidate);

        let mut hasher = DefaultHasher::new();
        src.hash(&mut hasher);
        candidate.id = hasher.finish();

        if !remotes.insert(candidate.clone()) {
            return;
        }
        drop(remotes);

        let mut checks = self.checks.lock().await;
        let pair = CandidatePair::new(None, candidate, self.is_controlling());
        let mut check = CheckPair {
            pair,
            trans: Transaction::init(),
            latency: u32::MAX,
        };

        check.trans.id = rand::random();
        check.pair.state = PairState::Waiting;
        enqueue_transaction(&mut check, Duration::default());

        checks.push(check);
        checks.sort_by_key(|it| it.pair.priority);
        drop(checks);

        self.notify.notify_one();
    }
}

fn enqueue_transaction(check: &mut CheckPair, delay: Duration) {
    check.trans.next_send = Instant::now() + delay;
    if check.pair.state == PairState::Waiting {
        check.trans.retry = DEFAULT_RETRY;
        check.trans.retry_timeout = DEFAULT_TIMEOUT;
    }
}
