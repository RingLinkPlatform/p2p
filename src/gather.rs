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
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use self::linux::try_get_local_address;
#[cfg(windows)]
use self::windows::try_get_local_address;
use crate::candidate::{compute_priority, Candidate, CandidateType};
#[cfg(feature = "upnp")]
pub use upnp::get_upnp_candidates;

#[cfg(feature = "upnp")]
mod upnp;

#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod linux;

/// gather local candidates
///
/// # Arguments
/// * `port` - local port to bind
/// * `max` - max candidates to gather
pub fn get_local_candidate(port: u16, max: u32) -> Vec<Candidate> {
    let address = try_get_local_address().unwrap_or_default();
    let mut candidates = address
        .into_iter()
        .map(|(name, addrs)| (name, addrs.into_iter().filter(|it| !is_local(it))))
        .enumerate()
        .map(|(if_idx, (name, addrs))| {
            // map IpAddr to Candidate
            addrs
                .into_iter()
                .map(|a| SocketAddr::new(a, port))
                .enumerate()
                .map(move |(idx, s)| {
                    let priority =
                        compute_priority(CandidateType::Host, s.is_ipv4(), (if_idx + idx) as u32);

                    // compute host candidate id use interface name and its address
                    // so we can identify this candidate when local candidates changed
                    let mut hasher = DefaultHasher::new();
                    name.hash(&mut hasher);
                    s.hash(&mut hasher);

                    let id = hasher.finish();

                    Candidate {
                        id,
                        typ: CandidateType::Host,
                        priority,
                        address: s,
                    }
                })
        })
        .flatten()
        .collect::<Vec<_>>();

    candidates.sort_by_key(|c| c.priority);
    candidates.truncate(max as usize);

    candidates
}

fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_multicast()
        }
    }
}
