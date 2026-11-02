//! NC02: how the macOS meter streams snapshots to the daemon. Other meters
//! produce [`SocketCount`] directly.

use super::{Proto, SocketCount};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC: &[u8] = b"NC02";

#[derive(Debug)]
pub enum FrameError {
    Truncated,
    BadMagic,
    BadType(u8),
    BadProto(u8),
    BadFamily(u8),
    Meter(String),
    Io(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "truncated meter frame"),
            FrameError::BadMagic => write!(f, "meter stream is not NC02"),
            FrameError::BadType(v) => write!(f, "unknown frame type {v}"),
            FrameError::BadProto(v) => write!(f, "unknown proto {v}"),
            FrameError::BadFamily(v) => write!(f, "unknown address family {v}"),
            FrameError::Meter(msg) => write!(f, "meter error: {msg}"),
            FrameError::Io(msg) => write!(f, "meter read failed: {msg}"),
        }
    }
}

/// Read one snapshot. The buffer must start with [`MAGIC`].
pub fn decode_sample(input: &mut &[u8]) -> Result<Vec<SocketCount>, FrameError> {
    if input.len() < 4 || &input[..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    *input = &input[4..];
    decode_one(input)
}

pub fn read_magic(reader: &mut impl Read) -> Result<(), FrameError> {
    let mut buf = [0u8; 4];
    reader
        .read_exact(&mut buf)
        .map_err(|err| FrameError::Io(err.to_string()))?;
    if &buf != MAGIC {
        return Err(FrameError::BadMagic);
    }
    Ok(())
}

pub fn read_sample(reader: &mut impl Read) -> Result<Vec<SocketCount>, FrameError> {
    let mut sockets = Vec::new();
    loop {
        let payload = read_payload(reader)?;
        match consume_payload(&payload, &mut sockets)? {
            Step::Continue => {}
            Step::Done => return Ok(sockets),
        }
    }
}

enum Step {
    Continue,
    Done,
}

fn decode_one(input: &mut &[u8]) -> Result<Vec<SocketCount>, FrameError> {
    let mut sockets = Vec::new();
    loop {
        let payload = pull_msg(input)?;
        match consume_payload(payload, &mut sockets)? {
            Step::Continue => {}
            Step::Done => return Ok(sockets),
        }
    }
}

fn consume_payload(payload: &[u8], sockets: &mut Vec<SocketCount>) -> Result<Step, FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Truncated);
    }
    match payload[0] {
        1 => Ok(Step::Continue),
        2 => {
            sockets.push(parse_socket(payload)?);
            Ok(Step::Continue)
        }
        3 => Ok(Step::Done),
        4 => Err(FrameError::Meter(
            String::from_utf8_lossy(&payload[1..]).into_owned(),
        )),
        other => Err(FrameError::BadType(other)),
    }
}

fn pull_msg<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], FrameError> {
    if input.len() < 4 {
        return Err(FrameError::Truncated);
    }
    let len = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if input.len() < len {
        return Err(FrameError::Truncated);
    }
    let (payload, rest) = input.split_at(len);
    *input = rest;
    Ok(payload)
}

fn read_payload(reader: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|err| FrameError::Io(err.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(FrameError::Meter("frame is too large".into()));
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|err| FrameError::Io(err.to_string()))?;
    Ok(payload)
}

fn parse_socket(payload: &[u8]) -> Result<SocketCount, FrameError> {
    // type, source, flags, pid, start, proto, name_len, name[64], local, remote, rx, tx,
    // path_len, path
    if payload.len() < 144 {
        return Err(FrameError::Truncated);
    }
    let source = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let new = payload[9] & 1 != 0;
    let pid = u32::from_le_bytes(payload[10..14].try_into().unwrap());
    let start_time = u64::from_le_bytes(payload[14..22].try_into().unwrap());
    let proto = match payload[22] {
        1 => Proto::Tcp,
        2 => Proto::Udp,
        other => return Err(FrameError::BadProto(other)),
    };
    let name_len = payload[23] as usize;
    if name_len > 64 {
        return Err(FrameError::Truncated);
    }
    let name = String::from_utf8_lossy(&payload[24..24 + name_len]).into_owned();
    let mut cursor = &payload[88..];
    let local = take_addr(&mut cursor)?;
    let remote = take_addr(&mut cursor)?;
    if cursor.len() < 18 {
        return Err(FrameError::Truncated);
    }
    let rx = u64::from_le_bytes(cursor[0..8].try_into().unwrap());
    let tx = u64::from_le_bytes(cursor[8..16].try_into().unwrap());
    let path_len = u16::from_le_bytes([cursor[16], cursor[17]]) as usize;
    let cursor = &cursor[18..];
    if cursor.len() < path_len {
        return Err(FrameError::Truncated);
    }
    let path = std::str::from_utf8(&cursor[..path_len])
        .ok()
        .filter(|text| text.starts_with('/'))
        .map(str::to_owned);
    Ok(SocketCount {
        source,
        new,
        pid,
        start_time,
        proto,
        name,
        local,
        remote,
        rx,
        tx,
        path,
    })
}

#[cfg(test)]
fn put_addr(buf: &mut Vec<u8>, addr: Option<SocketAddr>) {
    match addr {
        None => {
            buf.push(0);
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&[0u8; 16]);
        }
        Some(SocketAddr::V4(v4)) => {
            buf.push(4);
            buf.extend_from_slice(&v4.port().to_le_bytes());
            let mut raw = [0u8; 16];
            raw[..4].copy_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&raw);
        }
        Some(SocketAddr::V6(v6)) => {
            buf.push(6);
            buf.extend_from_slice(&v6.port().to_le_bytes());
            buf.extend_from_slice(&v6.ip().octets());
        }
    }
}

fn take_addr(input: &mut &[u8]) -> Result<Option<SocketAddr>, FrameError> {
    if input.len() < 1 + 2 + 16 {
        return Err(FrameError::Truncated);
    }
    let family = input[0];
    let port = u16::from_le_bytes([input[1], input[2]]);
    let raw = &input[3..19];
    *input = &input[19..];
    match family {
        0 => Ok(None),
        4 => {
            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)))
        }
        other => Err(FrameError::BadFamily(other)),
    }
}

/// Test helper. The C meter writes the same layout.
#[cfg(test)]
fn encode_sample(sockets: &[SocketCount]) -> Vec<u8> {
    fn msg(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    let mut out = Vec::from(MAGIC);
    out.extend(msg(&[1, 0, 0, 0, 0, 0, 0, 0, 0]));

    for sock in sockets {
        let mut payload = Vec::new();
        payload.push(2);
        payload.extend_from_slice(&sock.source.to_le_bytes());
        payload.push(u8::from(sock.new));
        payload.extend_from_slice(&sock.pid.to_le_bytes());
        payload.extend_from_slice(&sock.start_time.to_le_bytes());
        payload.push(match sock.proto {
            Proto::Tcp => 1,
            Proto::Udp => 2,
        });
        let name = sock.name.as_bytes();
        let name_len = name.len().min(64) as u8;
        payload.push(name_len);
        let mut name_buf = [0u8; 64];
        name_buf[..name_len as usize].copy_from_slice(&name[..name_len as usize]);
        payload.extend_from_slice(&name_buf);
        put_addr(&mut payload, sock.local);
        put_addr(&mut payload, sock.remote);
        payload.extend_from_slice(&sock.rx.to_le_bytes());
        payload.extend_from_slice(&sock.tx.to_le_bytes());
        let path = sock.path.as_deref().unwrap_or("").as_bytes();
        payload.extend_from_slice(&(path.len() as u16).to_le_bytes());
        payload.extend_from_slice(path);
        out.extend(msg(&payload));
    }

    let mut end = vec![3];
    end.extend_from_slice(&(sockets.len() as u32).to_le_bytes());
    out.extend(msg(&end));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock() -> SocketCount {
        SocketCount {
            source: 3,
            new: true,
            pid: 42,
            start_time: 1_700_000_000,
            proto: Proto::Tcp,
            name: "curl".into(),
            local: Some("10.0.0.5:40000".parse().unwrap()),
            remote: Some("1.1.1.1:443".parse().unwrap()),
            rx: 1000,
            tx: 200,
            path: Some("/usr/bin/curl".into()),
        }
    }

    #[test]
    fn round_trip_one_socket() {
        let bytes = encode_sample(&[sock()]);
        let mut input = bytes.as_slice();
        let decoded = decode_sample(&mut input).unwrap();
        assert_eq!(decoded, vec![sock()]);
        assert!(input.is_empty());
    }

    #[test]
    fn round_trip_without_a_path() {
        let mut quiet = sock();
        quiet.new = false;
        quiet.path = None;
        let bytes = encode_sample(&[quiet.clone()]);
        let decoded = decode_sample(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, vec![quiet]);
    }

    #[test]
    fn rejects_a_stream_without_magic() {
        let mut input = &b"XXXX"[..];
        match decode_sample(&mut input) {
            Err(FrameError::BadMagic) => {}
            other => panic!("expected bad magic, got {other:?}"),
        }
    }
}
