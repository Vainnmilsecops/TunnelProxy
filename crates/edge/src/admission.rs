//! Shared bounded per-source-IP connection admission.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(crate) struct PeerAdmission {
    max_connections_per_ip: usize,
    active: Mutex<HashMap<IpAddr, usize>>,
}

impl PeerAdmission {
    pub(crate) fn new(max_connections_per_ip: usize) -> Self {
        Self {
            max_connections_per_ip,
            active: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Option<PeerAdmissionPermit> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.get(&peer).copied().unwrap_or(0) >= self.max_connections_per_ip {
            return None;
        }
        *active.entry(peer).or_default() += 1;
        Some(PeerAdmissionPermit {
            admission: Arc::clone(self),
            peer,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PeerAdmissionPermit {
    admission: Arc<PeerAdmission>,
    peer: IpAddr,
}

impl Drop for PeerAdmissionPermit {
    fn drop(&mut self) {
        let mut active = self
            .admission
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(count) = active.get_mut(&self.peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&self.peer);
        }
    }
}
