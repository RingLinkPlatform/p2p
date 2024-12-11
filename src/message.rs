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

use std::fmt::Debug;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// similar to STUN bind message
#[derive(Debug, Serialize, Deserialize)]
pub struct BindMessage {
    /// random transaction id
    pub transaction_id: u64,

    pub body: BindBody,
}

impl BindMessage {
    /// create a new bind request
    pub fn request(request: BindRequest) -> Self {
        let transaction_id = rand::random();

        BindMessage {
            transaction_id,
            body: BindBody::Request(request),
        }
    }

    /// create a new bind response for a transaction
    pub fn response(transaction_id: u64, response: BindResponse) -> Self {
        BindMessage {
            transaction_id,
            body: BindBody::Response(response),
        }
    }

    /// encode this message to bytes using cbor
    pub fn encode<W>(&self, writer: W) -> Result<()>
    where
        W: ciborium_io::Write,
        W::Error: Debug + Send + Sync + 'static,
    {
        ciborium::ser::into_writer(&self, writer).map_err(Into::into)
    }

    /// decode a message from bytes
    pub fn decode<R>(reader: R) -> Result<Self>
    where
        R: ciborium_io::Read,
        R::Error: Debug + Send + Sync + 'static,
    {
        ciborium::de::from_reader(reader).map_err(Into::into)
    }
}

/// bind message body
#[derive(Debug, Serialize, Deserialize)]
pub enum BindBody {
    Request(BindRequest),
    Response(BindResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BindRequest {
    pub priority: u32,
    pub use_candidate: bool,
    pub controlling: Option<u64>,
    pub controlled: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BindResponse {
    pub error: u32,
    pub mapped_address: SocketAddr,
}
