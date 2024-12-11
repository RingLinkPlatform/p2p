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

use std::cmp::{max, min};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    Host,
    PeerReflexive,
    ServerReflexive,
    Relayed,
}

impl CandidateType {
    /// type preference
    ///
    /// RECOMMENDED from RFC8445 [5.1.2.2](https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.2)
    ///
    /// The RECOMMENDED values for type preferences are 126 for host
    /// candidates, 110 for peer-reflexive candidates, 100 for server-
    /// reflexive candidates, and 0 for relayed candidates.
    pub fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relayed => 0,
        }
    }
}

impl TryFrom<u32> for CandidateType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            126 => Ok(CandidateType::Host),
            110 => Ok(CandidateType::PeerReflexive),
            100 => Ok(CandidateType::ServerReflexive),
            0 => Ok(CandidateType::Relayed),
            _ => Err(value),
        }
    }
}

/// candidate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    /// unique id of this candidate
    pub id: u64,
    /// type of candidate
    pub typ: CandidateType,
    /// priority
    pub priority: u32,
    /// socket address, ip and port
    pub address: SocketAddr,
}

impl Eq for Candidate {}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id) && self.typ.eq(&other.typ) && self.address.eq(&other.address)
    }
}

impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} {}({:?})",
            self.id, self.priority, self.address, self.typ
        )
    }
}

impl Hash for Candidate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // skip location hash
        self.id.hash(state);
        self.typ.hash(state);
        self.address.hash(state);
    }
}

/// compute a candidate priority
///
/// # Arguments
/// * `typ` - candidate type
/// * `v4` - true if candidate is IPv4, false for IPv6
/// * `index` - index of candidate
pub fn compute_priority(typ: CandidateType, v4: bool, index: u32) -> u32 {
    let local_preference = if v4 { 32767u32 } else { 65535u32 };

    2u32.pow(24) * typ.type_preference()
        + 2u32.pow(8) * (local_preference - index.clamp(0, 32767))
        + 2u32.pow(0) * (256 - 1)
}

/// state of a candidate pair
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PairState {
    /// check has not been sent for this pair
    Waiting,
    /// a successful response received
    Succeed,
    /// * check timeout
    /// * a unrecoverable error response received
    Failed,
    /// check of pair is in-progress
    InProgress,
    /// pair is frozen, no check will be preformed
    Frozen,
}

#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Option<Candidate>,
    pub remote: Candidate,

    pub priority: u64,
    pub state: PairState,

    pub nominated: bool,
    pub nomination_requested: bool,
}

impl Display for CandidatePair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<{:?}> {{{} -> {}}} ",
            self.state,
            self.local
                .as_ref()
                .map(|it| format!("{}", it))
                .unwrap_or("*".to_string()),
            self.remote
        )?;
        match (self.nominated, self.nomination_requested) {
            (false, true) => write!(f, "[NR]")?,
            (false, false) => write!(f, "[_]")?,
            (true, _) => write!(f, "[N]")?,
        }

        Ok(())
    }
}

impl CandidatePair {
    pub fn failed(&mut self) {
        self.state = PairState::Failed;
        self.nominated = false;
        self.nomination_requested = false;
    }
}

impl CandidatePair {
    /// create a candidate pair
    ///
    /// # Arguments
    /// * `local` - local candidate
    /// * `remote` - remote candidate
    /// * `controlling` - whether agent role is CONTROLLING
    pub fn new(local: Option<Candidate>, remote: Candidate, controlling: bool) -> CandidatePair {
        let priority = pair_priority(&local, &remote, controlling);

        CandidatePair {
            local,
            remote,
            priority,
            state: PairState::Frozen,
            nominated: false,
            nomination_requested: false,
        }
    }

    pub fn set_role(&mut self, controlling: bool) {
        let priority = pair_priority(&self.local, &self.remote, controlling);

        self.priority = priority;
    }
}

/// compute priority of candidate pair
fn pair_priority(local: &Option<Candidate>, remote: &Candidate, controlling: bool) -> u64 {
    let local_priority = local.as_ref().map_or_else(
        || compute_priority(CandidateType::Host, remote.address.is_ipv4(), 0) as u64,
        |c| c.priority as u64,
    );
    let remote_priority = remote.priority as u64;

    let g = if controlling {
        local_priority
    } else {
        remote_priority
    };
    let d = if !controlling {
        local_priority
    } else {
        remote_priority
    };

    2u64.pow(32) * min(g, d) + 2 * max(g, d) + if g > d { 1 } else { 0 }
}

#[derive(Clone, Debug)]
pub(crate) struct InnerCandidate {
    iter: usize,
    pub(crate) candidate: Candidate,
}

#[derive(Default)]
struct InnerState {
    iter: AtomicUsize,
    candidates: Mutex<Vec<InnerCandidate>>,
}

/// LocalCandidates set
#[derive(Clone, Default)]
pub struct LocalCandidates {
    inner: Arc<InnerState>,
}

/// Max number of candidates per type
const MAX_CANDIDATE_PER_TYPE: usize = 5;

impl LocalCandidates {
    pub fn find<F>(&self, pred: F) -> Option<Candidate>
    where
        F: Fn(&Candidate) -> bool,
    {
        let candidates = self.inner.candidates.lock().unwrap();
        candidates.iter().map(|it| it.candidate.clone()).find(pred)
    }

    pub fn get(&self) -> Vec<Candidate> {
        let candidates = self.inner.candidates.lock().unwrap();
        candidates.iter().map(|it| it.candidate.clone()).collect()
    }

    pub fn exist_for_address(&self, address: SocketAddr) -> bool {
        let candidates = self.inner.candidates.lock().unwrap();
        candidates
            .iter()
            .find(|c| c.candidate.address == address)
            .is_some()
    }

    pub(crate) fn mut_on<F: FnOnce(&mut Vec<InnerCandidate>)>(&self, f: F) {
        let mut guard = self.inner.candidates.lock().unwrap();
        f(&mut guard);
    }

    /// Insert a new local candidate
    ///
    /// Only keep max [MAX_CANDIDATE_PER_TYPE] candidates for [CandidateType::PeerReflexive] and [CandidateType::ServerReflexive],
    /// old candidates with that type will be erased from local candidates
    pub fn insert(&self, mut candidate: Candidate) {
        let mut guard = self.inner.candidates.lock().unwrap();

        // don't add if already exist for given address and type
        if guard
            .iter()
            .find(|c| c.candidate.address == candidate.address && c.candidate.typ == candidate.typ)
            .is_some()
        {
            return;
        }

        let priority = compute_priority(
            candidate.typ,
            candidate.address.is_ipv4(),
            guard.len() as u32,
        );
        candidate.priority = priority;

        if candidate.id == 0 {
            let mut hasher = DefaultHasher::new();
            candidate.address.hash(&mut hasher);

            candidate.id = hasher.finish();
        }

        guard.push(InnerCandidate {
            iter: self.inner.iter.fetch_add(1, Ordering::Release),
            candidate: candidate.clone(),
        });

        if matches!(
            candidate.typ,
            CandidateType::PeerReflexive | CandidateType::ServerReflexive
        ) {
            for typ in [CandidateType::PeerReflexive, CandidateType::ServerReflexive] {
                let count = guard.iter().filter(|it| it.candidate.typ == typ).count();
                if count > MAX_CANDIDATE_PER_TYPE {
                    let (mut left, mut right) = guard
                        .iter()
                        .cloned()
                        .partition::<Vec<_>, _>(|c| c.candidate.typ != typ);

                    right.sort_by(|a, b| b.iter.cmp(&a.iter));
                    right.truncate(MAX_CANDIDATE_PER_TYPE);

                    left.extend(right);
                    *guard = left;
                }
            }
        }
    }
}

impl<T> From<T> for LocalCandidates
where
    T: IntoIterator<Item = Candidate>,
{
    fn from(value: T) -> Self {
        let candidates = value
            .into_iter()
            .enumerate()
            .map(|(idx, c)| InnerCandidate {
                iter: idx,
                candidate: c,
            })
            .collect::<Vec<_>>();

        LocalCandidates {
            inner: Arc::new(InnerState {
                iter: AtomicUsize::new(candidates.len() + 1),
                candidates: Mutex::new(candidates),
            }),
        }
    }
}
