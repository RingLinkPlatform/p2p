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

use std::error::Error as StdError;
use std::fmt::Debug;

pub(super) type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error {0}")]
    IO(#[from] std::io::Error),
    #[error("decode p2p message failed: {0}")]
    Decode(Box<dyn StdError + Send + Sync + 'static>),
    #[error("encode p2p message failed: {0}")]
    Encode(Box<dyn StdError + Send + Sync + 'static>),
    #[error("agent not connected")]
    Disconnected,
    #[error("unknown peer")]
    UnknownPeer,
    #[cfg(feature = "upnp")]
    #[error("upnp: {0}")]
    UPnP(#[from] rupnp::Error),
    #[error("invalid socket address: {0}")]
    InvalidSocketAddress(#[from] std::net::AddrParseError),
    #[error("invalid candidate type")]
    InvalidCandidateType,
    #[error("identity: {0}")]
    Identity(#[from] ringlink_identity::Error),
    #[error("invalid binding signature")]
    InvalidSignature,
}

impl<E> From<ciborium::de::Error<E>> for Error
where
    E: Debug + Send + Sync + 'static,
{
    fn from(this: ciborium::de::Error<E>) -> Self {
        Error::Decode(Box::new(this))
    }
}

impl<E> From<ciborium::ser::Error<E>> for Error
where
    E: Debug + Send + Sync + 'static,
{
    fn from(this: ciborium::ser::Error<E>) -> Self {
        Error::Encode(Box::new(this))
    }
}
