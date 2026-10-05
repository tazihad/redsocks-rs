use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ClientSessionInfo {
    pub client_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub proxy_type: String,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Default)]
pub struct StatsTracker {
    next_id: AtomicUsize,
    total_connections: AtomicU64,
    active_connections: AtomicUsize,
    clients: Mutex<HashMap<usize, ClientSessionInfo>>,
}

impl StatsTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn register_client(
        &self,
        client_addr: SocketAddr,
        dest_addr: SocketAddr,
        proxy_type: &str,
    ) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);

        let now = Instant::now();
        let info = ClientSessionInfo {
            client_addr,
            dest_addr,
            proxy_type: proxy_type.to_string(),
            connected_at: now,
            last_activity: now,
            bytes_up: 0,
            bytes_down: 0,
        };

        let mut lock = self.clients.lock().unwrap();
        lock.insert(id, info);
        id
    }

    pub fn update_activity(&self, id: usize, bytes_up: u64, bytes_down: u64) {
        let mut lock = self.clients.lock().unwrap();
        if let Some(info) = lock.get_mut(&id) {
            info.last_activity = Instant::now();
            info.bytes_up += bytes_up;
            info.bytes_down += bytes_down;
        }
    }

    pub fn unregister_client(&self, id: usize) {
        let mut lock = self.clients.lock().unwrap();
        if lock.remove(&id).is_some() {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn dump_clients(&self) {
        let lock = self.clients.lock().unwrap();
        let now = Instant::now();
        log::info!(
            "=== [SIGUSR1] Dumping active client list ({} clients) ===",
            lock.len()
        );

        for (id, client) in lock.iter() {
            let age = now.duration_since(client.connected_at).as_secs_f64();
            let idle = now.duration_since(client.last_activity).as_secs_f64();
            log::info!(
                "Client #{} [{}]: {} -> {}, age: {:.2}s, idle: {:.2}s, up: {} bytes, down: {} bytes",
                id,
                client.proxy_type,
                client.client_addr,
                client.dest_addr,
                age,
                idle,
                client.bytes_up,
                client.bytes_down
            );
        }
        log::info!("=== End of client list ===");
    }
}
