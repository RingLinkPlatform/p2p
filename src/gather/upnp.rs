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

use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use rupnp::ssdp::{SearchTarget, URN};
use tracing::debug;

use crate::candidate::compute_priority;
use crate::error::Result;
use crate::{Candidate, CandidateType};

const UPNP_DESC: &str = "RingLink";

pub async fn get_upnp_candidates(id: &str, port: u16) -> Result<Vec<Candidate>> {
    let mapping_addresses = get_externals(id).await?;

    let mut candidates = Vec::new();
    for mut mapping_address in mapping_addresses {
        mapping_address.set_port(port);

        debug!("UPnP address: {}", mapping_address);
        let priority = compute_priority(CandidateType::Host, mapping_address.is_ipv4(), 0);

        let mut hasher = DefaultHasher::new();
        mapping_address.hash(&mut hasher);
        UPNP_DESC.hash(&mut hasher);

        let id = hasher.finish();

        candidates.push(Candidate {
            id,
            typ: CandidateType::Host,
            priority,
            address: mapping_address,
        })
    }

    Ok(candidates)
}

const URN_DEVICE: URN = URN::device("schemas-upnp-org", "InternetGatewayDevice", 1);
const URN_SERVICE: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);

pub async fn get_externals(id: &str) -> Result<Vec<SocketAddr>, rupnp::Error> {
    let desc = format!("{}/{}", UPNP_DESC, id);

    let devices = rupnp::discover(&SearchTarget::URN(URN_DEVICE), Duration::from_secs(5)).await?;
    let mut devices = std::pin::pin!(devices);
    let mut externals = Vec::new();
    while let Some(device) = devices.next().await {
        let device = device?;

        for service in device
            .services_iter()
            .filter(|s| s.service_type() == &URN_SERVICE)
            .cloned()
            .collect::<Vec<_>>()
        {
            let out = service
                .action(device.url(), "GetExternalIPAddress", "")
                .await?;

            if let Some(external) = out
                .get("NewExternalIPAddress")
                .and_then(|it| IpAddr::from_str(it).ok())
            {
                for idx in 1..32 {
                    let arg = format!("<NewPortMappingIndex>{idx}</NewPortMappingIndex>");
                    let out = service
                        .action(device.url(), "GetGenericPortMappingEntry", &arg)
                        .await;

                    match out {
                        Ok(out) => {
                            let Some(entry_desc) = out.get("NewPortMappingDescription") else {
                                continue;
                            };

                            if &**entry_desc == desc {
                                if let Some(port) = out
                                    .get("NewExternalPort")
                                    .and_then(|p| u16::from_str(&**p).ok())
                                {
                                    externals.push(SocketAddr::new(external, port));
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    Ok(externals)
}
