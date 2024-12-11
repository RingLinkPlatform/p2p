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

use std::collections::HashMap;
use std::error::Error;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr};

use libc::{c_int, getifaddrs};

pub(crate) fn try_get_local_address() -> Result<Vec<(String, Vec<IpAddr>)>, Box<dyn Error>> {
    let mut ret = HashMap::<String, Vec<IpAddr>>::new();
    unsafe {
        let mut ifaddr = std::ptr::null_mut();
        let n = getifaddrs(&mut ifaddr);
        if n != 0 {
            return Err("getifaddrs failed".into());
        }

        let mut p = ifaddr;
        while !p.is_null() {
            let name = CStr::from_ptr((*p).ifa_name).to_string_lossy().to_string();
            let addr = (*p).ifa_addr;
            if !addr.is_null() {
                match (*addr).sa_family as c_int {
                    libc::AF_INET => {
                        let addr = addr.cast::<libc::sockaddr_in>();
                        let addr = Ipv4Addr::from((*addr).sin_addr.s_addr.to_be());

                        ret.entry(name).or_default().push(IpAddr::V4(addr));
                    }
                    _ => {}
                }
            }

            p = (*p).ifa_next;
        }

        libc::freeifaddrs(ifaddr);
    }

    Ok(ret.into_iter().collect())
}
