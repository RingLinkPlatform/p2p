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

use std::alloc::{alloc, dealloc, Layout};
use std::mem::align_of;
use std::net::IpAddr;
use std::ptr::NonNull;

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

pub(crate) fn try_get_local_address() -> Result<Vec<(String, Vec<IpAddr>)>, WIN32_ERROR> {
    use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
    let flags = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    struct DeferPointer<T> {
        layout: Layout,
        ptr: NonNull<T>,
    }
    impl<T> Drop for DeferPointer<T> {
        fn drop(&mut self) {
            unsafe {
                dealloc(self.ptr.as_ptr().cast(), self.layout);
            }
        }
    }

    unsafe {
        let mut size = 0;
        // todo: add ipv6 support
        let e = GetAdaptersAddresses(AF_INET.0 as u32, flags, None, None, &mut size);
        if e != ERROR_BUFFER_OVERFLOW.0 {
            return Err(WIN32_ERROR(e));
        }

        let layout =
            Layout::from_size_align(size as usize, align_of::<IP_ADAPTER_ADDRESSES_LH>()).unwrap();
        let ptr = DeferPointer {
            layout,
            ptr: NonNull::new_unchecked(alloc(layout).cast::<IP_ADAPTER_ADDRESSES_LH>()),
        };

        let e = GetAdaptersAddresses(
            AF_INET.0 as u32,
            flags,
            None,
            Some(ptr.ptr.as_ptr()),
            &mut size,
        );
        if e != 0 {
            return Err(WIN32_ERROR(e));
        }

        let mut ret = Vec::new();
        let mut walker = ptr.ptr.as_ptr();
        while !walker.is_null() {
            if (*walker).OperStatus == IfOperStatusUp {
                let adapter_name = (*walker).AdapterName.to_string().unwrap();
                let addrs = walk_address((*walker).FirstUnicastAddress);
                ret.push((adapter_name, addrs));
            }

            walker = (*walker).Next;
        }

        return Ok(ret);
    }

    unsafe fn walk_address(ptr: *mut IP_ADAPTER_UNICAST_ADDRESS_LH) -> Vec<IpAddr> {
        let mut ret = Vec::new();

        let mut walker = ptr;
        while !walker.is_null() {
            let addr = (*walker).Address.lpSockaddr;
            let family = (*addr).sa_family;

            match family {
                AF_INET => {
                    let sock_address = addr.cast::<SOCKADDR_IN>();
                    let addr = IpAddr::from((*sock_address).sin_addr.S_un.S_addr.to_ne_bytes());

                    ret.push(addr);
                }
                AF_INET6 => {
                    let sock_address = addr.cast::<SOCKADDR_IN6>();
                    let addr = IpAddr::from((*sock_address).sin6_addr.u.Byte);

                    ret.push(addr);
                }
                _ => {}
            }

            walker = (*walker).Next;
        }

        ret
    }
}
