struct Hy2RealmRuntimeState {
    control: Hy2RealmControlClient,
    realm_id: String,
    stun_servers: Vec<String>,
    session_id: Mutex<String>,
    ttl_secs: Mutex<u64>,
    published_addresses: Mutex<Vec<SocketAddr>>,
    stun_waiters: Mutex<BTreeMap<Hy2RealmStunTransactionId, mpsc::SyncSender<SocketAddr>>>,
    punch_waiters:
        Mutex<Vec<(Hy2RealmPunchMetadata, mpsc::SyncSender<(SocketAddr, Hy2RealmPunchPacketType)>)>>,
}
