// Streaming WebSocket frame-mask translator for the cross-protocol
// upgrade bridge (issue #35).
//
// RFC 6455 §5.3 (HTTP/1.1 WebSocket) requires every client-to-server
// frame to carry a 4-byte masking key and to XOR its payload with it.
// RFC 8441 §5.5 (WebSocket over HTTP/2) drops masking entirely -- the
// MASK bit is always 0 and there is no masking key, because HTTP/2's
// framing already provides the property masking was invented to
// guarantee.  RFC 9220 extends the same unmasked convention to HTTP/3.
//
// When the proxy bridges an h1 client to an h2/h3 backend (or the
// reverse), the *client-to-server* frames cross that masking boundary
// and must be rewritten frame by frame.  Server-to-client frames are
// unmasked in *both* worlds, so that direction is a verbatim byte copy
// handled by the caller -- this module only ever sees the masked
// boundary.
//
// The translator is fully streaming: a frame's payload may be up to
// 2^63 bytes, so we never buffer a whole frame.  We parse the (small,
// <= 14 byte) header, emit the rewritten header immediately, then
// stream the payload through in bounded chunks, carrying the XOR key
// offset across chunk boundaries.

use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Which way the masking boundary is being crossed on the
/// client-to-server path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskMode {
    /// h1 client -> h2/h3 backend: incoming client frames are masked;
    /// strip the mask bit + key and unmask the payload.
    Unmask,
    /// h2/h3 client -> h1 backend: incoming client frames are
    /// unmasked; generate a fresh key, set the mask bit, mask the
    /// payload.
    Mask,
}

/// Parsed WebSocket frame header -- everything on the wire before the
/// payload bytes begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    /// Byte 0 verbatim: FIN + RSV1-3 + 4-bit opcode.  Preserved
    /// unchanged through translation (masking never touches it).
    pub fin_rsv_opcode: u8,
    /// Whether the inbound frame set the MASK bit.
    pub masked: bool,
    /// The inbound masking key (meaningful only when `masked`).
    pub mask_key: [u8; 4],
    /// Decoded payload length (after 126/127 extended-length decode).
    pub payload_len: u64,
    /// Total header size consumed from the wire, in bytes.
    pub header_len: usize,
}

/// Try to parse a frame header from the front of `buf`.
///
/// Returns `Ok(Some(header))` when a complete header is present,
/// `Ok(None)` when more bytes are needed (caller reads + retries),
/// and `Err` only on an impossible length encoding.
pub(crate) fn parse_header(
    buf: &[u8],
) -> io::Result<Option<FrameHeader>> {
    // Need at least the two fixed bytes.
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let masked = b1 & 0x80 != 0;
    let len7 = b1 & 0x7f;
    let mut idx = 2usize;

    let payload_len = match len7 {
        126 => {
            if buf.len() < idx + 2 {
                return Ok(None);
            }
            let l = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
            idx += 2;
            l as u64
        }
        127 => {
            if buf.len() < idx + 8 {
                return Ok(None);
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[idx..idx + 8]);
            idx += 8;
            let l = u64::from_be_bytes(a);
            // RFC 6455 §5.2: the high bit of a 64-bit length MUST be
            // 0.  Reject rather than risk a nonsensical frame.
            if l & 0x8000_0000_0000_0000 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ws: 64-bit frame length has high bit set",
                ));
            }
            l
        }
        n => n as u64,
    };

    let mut mask_key = [0u8; 4];
    if masked {
        if buf.len() < idx + 4 {
            return Ok(None);
        }
        mask_key.copy_from_slice(&buf[idx..idx + 4]);
        idx += 4;
    }

    Ok(Some(FrameHeader {
        fin_rsv_opcode: b0,
        masked,
        mask_key,
        payload_len,
        header_len: idx,
    }))
}

/// Serialise a frame header with the chosen mask state.  `mask_key` is
/// `Some` to set the MASK bit + emit the key, `None` to emit an
/// unmasked header.  `fin_rsv_opcode` and `payload_len` carry through
/// from the source frame unchanged.
pub(crate) fn emit_header(
    out: &mut Vec<u8>,
    fin_rsv_opcode: u8,
    payload_len: u64,
    mask_key: Option<[u8; 4]>,
) {
    out.push(fin_rsv_opcode);
    let mask_bit = if mask_key.is_some() { 0x80 } else { 0 };
    // Re-encode the length in the *shortest* form, mirroring how a
    // conformant endpoint would have framed it.  The source frame's
    // chosen encoding isn't observable to us beyond the decoded value,
    // and the canonical short form is always valid.
    if payload_len < 126 {
        out.push(mask_bit | payload_len as u8);
    } else if payload_len <= u16::MAX as u64 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&payload_len.to_be_bytes());
    }
    if let Some(k) = mask_key {
        out.extend_from_slice(&k);
    }
}

/// Generate a fresh 4-byte masking key.  RFC 6455 §5.3 requires the
/// key be unpredictable; we draw from the OS CSPRNG (same source the
/// JWT signer uses).
fn random_mask() -> [u8; 4] {
    use rand_core::{OsRng, RngCore};
    let mut k = [0u8; 4];
    OsRng.fill_bytes(&mut k);
    k
}

/// Internal frame-streaming state machine.
enum State {
    /// Accumulating bytes until a full frame header parses.
    Header,
    /// Streaming a frame's payload, XORing each byte with
    /// `eff[(offset + i) % 4]`.  `eff` is the effective per-position
    /// key: inbound_key XOR outbound_key (either may be the zero key
    /// when that side is unmasked), so a single XOR pass simultaneously
    /// unmasks the input and masks the output.
    Payload { remaining: u64, eff: [u8; 4], offset: u64 },
}

/// Translate the masking of a one-directional WebSocket frame stream,
/// reading from `reader` and writing rewritten frames to `writer`.
///
/// Runs until the reader reaches a clean frame boundary at EOF
/// (`Ok(())`), or a transport / truncation error occurs.  The payload
/// is streamed in 64 KiB chunks so memory stays bounded regardless of
/// frame size.
pub async fn translate_masking<R, W>(
    reader: &mut R,
    writer: &mut W,
    mode: MaskMode,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut acc = BytesMut::with_capacity(16 * 1024);
    let mut read_buf = vec![0u8; 64 * 1024];
    let mut state = State::Header;

    loop {
        match &mut state {
            State::Header => match parse_header(&acc)? {
                Some(h) => {
                    // The outbound mask state is fixed by `mode`; the
                    // inbound key comes from the parsed header.  XORing
                    // by (in_key XOR out_key) per position both removes
                    // the inbound mask and applies the outbound one.
                    let out_key = match mode {
                        MaskMode::Mask => Some(random_mask()),
                        MaskMode::Unmask => None,
                    };
                    let in_key =
                        if h.masked { Some(h.mask_key) } else { None };
                    let mut eff = [0u8; 4];
                    for j in 0..4 {
                        eff[j] = in_key.map_or(0, |k| k[j])
                            ^ out_key.map_or(0, |k| k[j]);
                    }

                    let mut hdr = Vec::with_capacity(14);
                    emit_header(
                        &mut hdr,
                        h.fin_rsv_opcode,
                        h.payload_len,
                        out_key,
                    );
                    writer.write_all(&hdr).await?;

                    let _ = acc.split_to(h.header_len);
                    state = State::Payload {
                        remaining: h.payload_len,
                        eff,
                        offset: 0,
                    };
                }
                None => {
                    // Header incomplete -- pull more bytes.  EOF here is
                    // only clean if there is nothing buffered at all
                    // (i.e. we are exactly between frames).
                    let n = reader.read(&mut read_buf).await?;
                    if n == 0 {
                        if acc.is_empty() {
                            return Ok(());
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: partial frame header at EOF",
                        ));
                    }
                    acc.extend_from_slice(&read_buf[..n]);
                }
            },
            State::Payload { remaining, eff, offset } => {
                if *remaining == 0 {
                    // Zero-length frame (e.g. an empty Close or a
                    // keepalive Ping) lands here immediately.
                    state = State::Header;
                    continue;
                }
                if acc.is_empty() {
                    let n = reader.read(&mut read_buf).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: truncated frame payload at EOF",
                        ));
                    }
                    acc.extend_from_slice(&read_buf[..n]);
                }
                let take =
                    std::cmp::min(*remaining, acc.len() as u64) as usize;
                let mut chunk = acc.split_to(take);
                // Skip the XOR pass entirely when both sides are
                // unmasked (eff is all-zero) -- e.g. an h2->h2 frame
                // that happens to flow through here.
                if *eff != [0u8; 4] {
                    for (i, b) in chunk.iter_mut().enumerate() {
                        let p = *offset + i as u64;
                        *b ^= eff[(p % 4) as usize];
                    }
                }
                writer.write_all(&chunk).await?;
                *offset += take as u64;
                *remaining -= take as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single WebSocket frame on the wire, masking the payload
    /// with `mask_key` when provided.  Used to synthesise client
    /// (masked) and server (unmasked) frames for the codec tests.
    fn build_frame(
        fin_rsv_opcode: u8,
        payload: &[u8],
        mask_key: Option<[u8; 4]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        emit_header(
            &mut out,
            fin_rsv_opcode,
            payload.len() as u64,
            mask_key,
        );
        match mask_key {
            Some(k) => out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ k[i % 4]),
            ),
            None => out.extend_from_slice(payload),
        }
        out
    }

    /// Run the translator over `input` and collect the rewritten wire
    /// bytes.  A duplex feeds `input` in, the translator writes into
    /// another duplex we drain.
    async fn run_translate(
        input: Vec<u8>,
        mode: MaskMode,
    ) -> Vec<u8> {
        let mut reader = std::io::Cursor::new(input);
        let mut output: Vec<u8> = Vec::new();
        translate_masking(&mut reader, &mut output, mode)
            .await
            .expect("translate clean");
        output
    }

    #[test]
    fn parse_header_short_form() {
        // 5-byte unmasked text frame.
        let frame = build_frame(0x81, b"hello", None);
        let h = parse_header(&frame).unwrap().unwrap();
        assert_eq!(h.fin_rsv_opcode, 0x81);
        assert!(!h.masked);
        assert_eq!(h.payload_len, 5);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn parse_header_needs_more_bytes() {
        // Only the first of two fixed bytes is present.
        assert!(parse_header(&[0x81]).unwrap().is_none());
        // 126 length form announced but extended length truncated.
        assert!(parse_header(&[0x81, 126, 0x00]).unwrap().is_none());
        // Masked bit set but key truncated.
        assert!(
            parse_header(&[0x81, 0x82, 0xaa, 0xbb])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parse_header_126_extended_length() {
        let payload = vec![0x5a; 200]; // > 125 -> 126 form
        let frame = build_frame(0x82, &payload, None);
        let h = parse_header(&frame).unwrap().unwrap();
        assert_eq!(h.payload_len, 200);
        assert_eq!(h.header_len, 4); // 2 fixed + 2 extended
    }

    #[test]
    fn parse_header_127_extended_length() {
        // Announce a 127 (64-bit) length without supplying the whole
        // payload -- we only check header decode here.
        let mut frame = vec![0x82, 127];
        frame.extend_from_slice(&70_000u64.to_be_bytes());
        let h = parse_header(&frame).unwrap().unwrap();
        assert_eq!(h.payload_len, 70_000);
        assert_eq!(h.header_len, 10); // 2 fixed + 8 extended
    }

    #[test]
    fn parse_header_127_masked() {
        let mut frame = vec![0x82, 127 | 0x80];
        frame.extend_from_slice(&70_000u64.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]); // mask key
        let h = parse_header(&frame).unwrap().unwrap();
        assert!(h.masked);
        assert_eq!(h.mask_key, [1, 2, 3, 4]);
        assert_eq!(h.header_len, 14); // 2 + 8 + 4
    }

    #[test]
    fn parse_header_rejects_high_bit_64() {
        let mut frame = vec![0x82, 127];
        frame.extend_from_slice(&0x8000_0000_0000_0001u64.to_be_bytes());
        assert!(parse_header(&frame).is_err());
    }

    #[tokio::test]
    async fn unmask_strips_mask_and_recovers_payload() {
        // h1 client -> h2 backend: masked text frame becomes an
        // unmasked text frame with identical payload + opcode.
        let mask = [0x12, 0x34, 0x56, 0x78];
        let frame = build_frame(0x81, b"cross-proto-ping", Some(mask));
        let out = run_translate(frame, MaskMode::Unmask).await;

        let h = parse_header(&out).unwrap().unwrap();
        assert_eq!(h.fin_rsv_opcode, 0x81);
        assert!(!h.masked, "output must drop the mask bit");
        assert_eq!(h.payload_len, 16);
        assert_eq!(&out[h.header_len..], b"cross-proto-ping");
    }

    #[tokio::test]
    async fn mask_adds_mask_and_payload_round_trips() {
        // h2 client -> h1 backend: unmasked frame becomes masked.
        // We can't predict the random key, so unmask using the key the
        // translator chose and check the payload survives.
        let frame = build_frame(0x81, b"to-h1-backend", None);
        let out = run_translate(frame, MaskMode::Mask).await;

        let h = parse_header(&out).unwrap().unwrap();
        assert!(h.masked, "output must set the mask bit");
        assert_eq!(h.payload_len, 13);
        let unmasked: Vec<u8> = out[h.header_len..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ h.mask_key[i % 4])
            .collect();
        assert_eq!(unmasked, b"to-h1-backend");
    }

    #[tokio::test]
    async fn unmask_sub_4_byte_payload() {
        // Payload shorter than the 4-byte key exercises the partial
        // key-offset path (only key[0..len] are touched).
        let mask = [0xde, 0xad, 0xbe, 0xef];
        let frame = build_frame(0x82, b"ab", Some(mask));
        let out = run_translate(frame, MaskMode::Unmask).await;
        let h = parse_header(&out).unwrap().unwrap();
        assert!(!h.masked);
        assert_eq!(&out[h.header_len..], b"ab");
    }

    #[tokio::test]
    async fn unmask_control_frame_mid_stream() {
        // A masked Ping (opcode 0x9) between two text frames must be
        // translated too, with its FIN/opcode byte preserved.
        let mask = [1, 2, 3, 4];
        let mut wire = build_frame(0x81, b"first", Some(mask));
        wire.extend(build_frame(0x89, b"pong-me", Some(mask))); // ping
        wire.extend(build_frame(0x81, b"third", Some(mask)));
        let out = run_translate(wire, MaskMode::Unmask).await;

        // Walk the three output frames back out.
        let mut off = 0;
        let expect: &[(u8, &[u8])] = &[
            (0x81, b"first"),
            (0x89, b"pong-me"),
            (0x81, b"third"),
        ];
        for (opcode, payload) in expect {
            let h = parse_header(&out[off..]).unwrap().unwrap();
            assert_eq!(h.fin_rsv_opcode, *opcode);
            assert!(!h.masked);
            let start = off + h.header_len;
            let end = start + h.payload_len as usize;
            assert_eq!(&out[start..end], *payload);
            off = end;
        }
        assert_eq!(off, out.len());
    }

    #[tokio::test]
    async fn unmask_large_payload_spans_chunks() {
        // A payload larger than the 64 KiB read buffer forces the
        // key-offset to carry across multiple read/write chunks.
        let mask = [0x11, 0x22, 0x33, 0x44];
        let payload: Vec<u8> =
            (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let frame = build_frame(0x82, &payload, Some(mask));
        let out = run_translate(frame, MaskMode::Unmask).await;

        let h = parse_header(&out).unwrap().unwrap();
        assert!(!h.masked);
        assert_eq!(h.payload_len, payload.len() as u64);
        assert_eq!(&out[h.header_len..], &payload[..]);
    }

    #[tokio::test]
    async fn zero_length_frame_translates() {
        // An empty masked Close frame (opcode 0x8, no payload).
        let frame = build_frame(0x88, b"", Some([9, 9, 9, 9]));
        let out = run_translate(frame, MaskMode::Unmask).await;
        let h = parse_header(&out).unwrap().unwrap();
        assert_eq!(h.fin_rsv_opcode, 0x88);
        assert!(!h.masked);
        assert_eq!(h.payload_len, 0);
        assert_eq!(out.len(), h.header_len);
    }

    #[tokio::test]
    async fn partial_header_at_eof_errors() {
        // A lone byte that can't form a header is a truncation, not a
        // clean close.
        let mut reader = std::io::Cursor::new(vec![0x81u8]);
        let mut out: Vec<u8> = Vec::new();
        let err = translate_masking(
            &mut reader,
            &mut out,
            MaskMode::Unmask,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
