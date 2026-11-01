//! QUIC Initial uses public version salts and DCIDs. Only authenticated Initial
//! CRYPTO frames are inspected; 0/1-RTT application traffic is never decrypted.
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct QuicInitialCrypto {
    pub dcid: Vec<u8>,
    pub fragments: Vec<(usize, Vec<u8>)>,
}
const V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const D29: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];
fn label(h: &Hkdf<Sha256>, name: &str, n: usize) -> Option<Vec<u8>> {
    let name = format!("tls13 {name}");
    let mut info = Vec::new();
    info.extend_from_slice(&(n as u16).to_be_bytes());
    info.push(name.len() as u8);
    info.extend_from_slice(name.as_bytes());
    info.push(0);
    let mut value = vec![0; n];
    h.expand(&info, &mut value).ok()?;
    Some(value)
}
fn varint(data: &[u8], p: &mut usize) -> Option<u64> {
    let byte = *data.get(*p)?;
    let n = 1usize << (byte >> 6);
    let slice = data.get(*p..*p + n)?;
    *p += n;
    let mut value = u64::from(byte & 0x3f);
    for byte in &slice[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}
pub fn sniff_quic_initial(data: &[u8]) -> Option<QuicInitialCrypto> {
    let mut start = 0;
    let mut result = None;
    while start + 7 <= data.len() {
        let first = data[start];
        if first & 0xc0 != 0xc0 {
            break;
        }
        let version = u32::from_be_bytes(data.get(start + 1..start + 5)?.try_into().ok()?);
        let (salt, prefix, initial) = match version {
            1 => (&V1, "quic", 0),
            0x6b3343cf => (&V2, "quicv2", 1),
            0xff00001d => (&D29, "quic", 0),
            _ => return result,
        };
        let packet_type = (first >> 4) & 3;
        let zero_rtt = if version == 0x6b3343cf { 2 } else { 1 };
        if packet_type != initial && packet_type != zero_rtt {
            break;
        }
        let mut p = start + 5;
        let n = *data.get(p)? as usize;
        p += 1;
        if n > 20 || n == 0 {
            return None;
        }
        let dcid = data.get(p..p + n)?;
        p += n;
        let n = *data.get(p)? as usize;
        p += 1;
        if n > 20 {
            return None;
        }
        p = p.checked_add(n)?;
        if p > data.len() {
            return None;
        }
        if packet_type == zero_rtt {
            let size = usize::try_from(varint(data, &mut p)?).ok()?;
            let end = p.checked_add(size).filter(|end| *end <= data.len())?;
            let record = result.get_or_insert_with(|| QuicInitialCrypto {
                dcid: dcid.to_vec(),
                fragments: Vec::new(),
            });
            if record.dcid != dcid {
                return None;
            }
            start = end;
            continue;
        }
        let token = usize::try_from(varint(data, &mut p)?).ok()?;
        p = p.checked_add(token)?;
        if p > data.len() {
            return None;
        }
        let size = usize::try_from(varint(data, &mut p)?).ok()?;
        let end = p.checked_add(size).filter(|end| *end <= data.len())?;
        let sample = data.get(p + 4..p + 20).filter(|_| p + 20 <= end)?;
        let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
        let client = label(&initial, "client in", 32)?;
        let client = Hkdf::<Sha256>::from_prk(&client).ok()?;
        let hp = label(&client, &format!("{prefix} hp"), 16)?;
        let aes = aes::Aes128::new_from_slice(&hp).ok()?;
        let mut mask = aes::cipher::Block::<aes::Aes128>::clone_from_slice(sample);
        aes.encrypt_block(&mut mask);
        let first = first ^ (mask[0] & 0x0f);
        if first & 0x0c != 0 {
            return None;
        }
        let pn_len = (first & 3) as usize + 1;
        if p + pn_len + 16 > end {
            return None;
        }
        let mut aad = data[start..p + pn_len].to_vec();
        aad[0] = first;
        let mut pn = 0u64;
        for i in 0..pn_len {
            let byte = data[p + i] ^ mask[i + 1];
            aad[p - start + i] = byte;
            pn = (pn << 8) | u64::from(byte);
        }
        let key = label(&client, &format!("{prefix} key"), 16)?;
        let mut iv = label(&client, &format!("{prefix} iv"), 12)?;
        for (a, b) in iv[4..].iter_mut().zip(pn.to_be_bytes()) {
            *a ^= b;
        }
        let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
        let plain = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&iv),
                Payload {
                    msg: &data[p + pn_len..end],
                    aad: &aad,
                },
            )
            .ok()?;
        let chunks = frames(&plain)?;
        let record = result.get_or_insert_with(|| QuicInitialCrypto {
            dcid: dcid.to_vec(),
            fragments: Vec::new(),
        });
        if record.dcid != dcid {
            return None;
        }
        record.fragments.extend(chunks);
        start = end;
    }
    result
}
fn frames(data: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    let mut result = Vec::new();
    let mut p = 0;
    let mut count = 0;
    while p < data.len() {
        count += 1;
        if count > 4096 {
            return None;
        }
        let kind = varint(data, &mut p)?;
        match kind {
            0 | 1 => {}
            2 | 3 => {
                varint(data, &mut p)?;
                varint(data, &mut p)?;
                let ranges = varint(data, &mut p)?;
                if ranges > 1024 {
                    return None;
                }
                varint(data, &mut p)?;
                for _ in 0..ranges {
                    varint(data, &mut p)?;
                    varint(data, &mut p)?;
                }
                if kind == 3 {
                    for _ in 0..3 {
                        varint(data, &mut p)?;
                    }
                }
            }
            6 => {
                let offset = usize::try_from(varint(data, &mut p)?).ok()?;
                let n = usize::try_from(varint(data, &mut p)?).ok()?;
                let end = p.checked_add(n).filter(|end| *end <= data.len())?;
                if offset.checked_add(n)? > 16384 {
                    return None;
                }
                result.push((offset, data[p..end].to_vec()));
                p = end;
            }
            _ => break,
        }
    }
    Some(result)
}
