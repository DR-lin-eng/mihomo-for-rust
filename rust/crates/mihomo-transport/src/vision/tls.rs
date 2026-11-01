//! Bounded TLS probing. Read/write fragments must never share a parser buffer.
const MAX_RECORD: usize = 16 * 1024 + 2048;
const MAX_HELLO: usize = 64 * 1024;

#[derive(Default)]
struct Probe {
    record: Vec<u8>,
    hello: Vec<u8>,
    stopped: bool,
}

pub(super) struct VisionTlsState {
    pub packets_to_filter: usize,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub enable_xtls: bool,
    read: Probe,
    write: Probe,
}

impl Default for VisionTlsState {
    fn default() -> Self {
        Self {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            read: Probe::default(),
            write: Probe::default(),
        }
    }
}

impl VisionTlsState {
    pub fn filter_tls(&mut self, bytes: &[u8]) {
        self.filter(bytes, false);
    }
    pub fn filter_read_tls(&mut self, bytes: &[u8]) {
        self.filter(bytes, true);
    }

    fn filter(&mut self, mut bytes: &[u8], reading: bool) {
        if self.packets_to_filter == 0 || bytes.is_empty() {
            return;
        }
        let probe = if reading {
            &mut self.read
        } else {
            &mut self.write
        };
        if probe.stopped {
            self.packets_to_filter = self.packets_to_filter.saturating_sub(1);
            return;
        }
        while !bytes.is_empty() && self.packets_to_filter > 0 {
            let needed = if probe.record.len() < 5 {
                5
            } else {
                5 + u16::from_be_bytes([probe.record[3], probe.record[4]]) as usize
            };
            let take = (needed - probe.record.len()).min(bytes.len());
            probe.record.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if probe.record.len() < 5 {
                break;
            }
            let record_len = u16::from_be_bytes([probe.record[3], probe.record[4]]) as usize;
            if !matches!(probe.record[0], 20..=23)
                || probe.record[1] != 3
                || probe.record[2] > 3
                || record_len > MAX_RECORD
            {
                probe.stopped = true;
                probe.record.clear();
                self.packets_to_filter = self.packets_to_filter.saturating_sub(1);
                break;
            }
            if probe.record.len() < record_len + 5 {
                continue;
            }
            self.packets_to_filter = self.packets_to_filter.saturating_sub(1);
            if probe.record[0] == 22 {
                if probe.hello.len() + record_len > MAX_HELLO {
                    probe.stopped = true;
                    probe.hello.clear();
                } else {
                    probe.hello.extend_from_slice(&probe.record[5..]);
                    if let Some(kind @ (1 | 2)) = probe.hello.first() {
                        self.is_tls = true;
                        if *kind == 2 {
                            self.is_tls12_or_above = true;
                        }
                    }
                    if probe.hello.len() >= 4 {
                        let len = ((probe.hello[1] as usize) << 16)
                            | ((probe.hello[2] as usize) << 8)
                            | probe.hello[3] as usize;
                        if len > MAX_HELLO - 4 {
                            probe.stopped = true;
                        } else if probe.hello.len() >= len + 4 {
                            if probe.hello[0] == 2 {
                                self.enable_xtls =
                                    server_hello_supports_direct(&probe.hello[4..4 + len]);
                                self.packets_to_filter = 0;
                            }
                            probe.hello.clear();
                        }
                    }
                }
            }
            probe.record.clear();
        }
    }
}

fn server_hello_supports_direct(hello: &[u8]) -> bool {
    if hello.len() < 40 || hello[..2] != [3, 3] {
        return false;
    }
    let sid_len = hello[34] as usize;
    if sid_len > 32 {
        return false;
    }
    let cipher_offset = 35 + sid_len;
    if hello.len() < cipher_offset + 5 {
        return false;
    }
    let cipher = u16::from_be_bytes([hello[cipher_offset], hello[cipher_offset + 1]]);
    if !matches!(cipher, 0x1301..=0x1304) || hello[cipher_offset + 2] != 0 {
        return false;
    }
    let len = u16::from_be_bytes([hello[cipher_offset + 3], hello[cipher_offset + 4]]) as usize;
    let mut extensions = &hello[cipher_offset + 5..];
    if extensions.len() != len {
        return false;
    }
    let mut tls13 = false;
    while extensions.len() >= 4 {
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        if extensions.len() < 4 + len {
            return false;
        }
        if kind == 43 {
            if tls13 || extensions[4..4 + len] != [3, 4] {
                return false;
            }
            tls13 = true;
        }
        extensions = &extensions[4 + len..];
    }
    tls13 && extensions.is_empty()
}
