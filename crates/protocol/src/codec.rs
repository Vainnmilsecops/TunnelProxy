//! Async frame encoder and decoder for Tunnel Protocol v2.
//!
//! Both the encoder and decoder operate on Tokio `AsyncRead` / `AsyncWrite`
//! streams and handle partial reads and writes correctly.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::frame::{Frame, FrameType, StreamId};
use crate::wire::{HEADER_SIZE, MAGIC, MAX_FRAME_PAYLOAD, VERSION};

/// Async frame encoder.
///
/// Writes complete frames to an `AsyncWrite` stream, handling partial
/// writes via `write_all` semantics.
#[derive(Debug)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encodes a complete frame and writes it to `writer`.
    ///
    /// Returns the number of bytes written (always `HEADER_SIZE + payload.len()`).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `frame.payload.len() > MAX_FRAME_PAYLOAD`
    /// - `frame` has invalid stream scope for its `frame_type`
    /// - An I/O error occurs while writing
    pub async fn encode<W: AsyncWrite + Unpin>(
        writer: &mut W,
        frame: &Frame,
    ) -> Result<usize, ProtocolError> {
        // Validate before constructing the header.
        Self::validate_frame(frame)?;

        let payload_len = u32::try_from(frame.payload.len())
            .map_err(|_| ProtocolError::EncodeFrameTooLarge(u32::MAX))?;

        // Build the 16-byte header.
        let mut header = [0u8; HEADER_SIZE as usize];

        // MAGIC (offset 0, 4 bytes)
        header[0..4].copy_from_slice(&MAGIC);

        // Version (offset 4, 1 byte)
        header[4] = VERSION;

        // Frame type (offset 5, 1 byte)
        header[5] = frame.frame_type.as_u8();

        // Flags (offset 6-7, 2 bytes big-endian)
        header[6] = (frame.flags >> 8) as u8;
        header[7] = frame.flags as u8;

        // Stream ID (offset 8-11, 4 bytes big-endian)
        let stream_id = frame.stream_id.get();
        header[8] = (stream_id >> 24) as u8;
        header[9] = (stream_id >> 16) as u8;
        header[10] = (stream_id >> 8) as u8;
        header[11] = stream_id as u8;

        // Payload length (offset 12-15, 4 bytes big-endian)
        header[12] = (payload_len >> 24) as u8;
        header[13] = (payload_len >> 16) as u8;
        header[14] = (payload_len >> 8) as u8;
        header[15] = payload_len as u8;

        // Write header.
        writer.write_all(&header).await?;
        // Write payload.
        writer.write_all(&frame.payload).await?;

        Ok(HEADER_SIZE as usize + frame.payload.len())
    }

    fn validate_frame(frame: &Frame) -> Result<(), ProtocolError> {
        // Payload size.
        let len = u32::try_from(frame.payload.len())
            .map_err(|_| ProtocolError::EncodeFrameTooLarge(u32::MAX))?;
        if len > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::EncodeFrameTooLarge(len));
        }

        // Flags.
        if frame.flags != 0 {
            return Err(ProtocolError::UnsupportedFlags(frame.flags));
        }

        // Stream scope.
        match frame.frame_type.scope() {
            crate::frame::Scope::Control => {
                if !frame.stream_id.is_control() {
                    return Err(ProtocolError::InvalidStreamScope {
                        frame_type: frame.frame_type,
                        required: "0 (control)",
                        got: frame.stream_id.get(),
                    });
                }
            }
            crate::frame::Scope::Stream => {
                if frame.stream_id.is_control() {
                    return Err(ProtocolError::InvalidStreamScope {
                        frame_type: frame.frame_type,
                        required: "> 0 (stream)",
                        got: frame.stream_id.get(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Async frame decoder.
///
/// Reads frames from an `AsyncRead` stream, handling fragmentation
/// and coalescing correctly.
///
/// # EOF semantics
///
/// - `Ok(None)` — clean EOF before any byte of the next frame header.
/// - `Err(ProtocolError::TruncatedHeader)` — partial header then EOF.
/// - `Err(ProtocolError::TruncatedPayload { .. })` — partial payload then EOF.
#[derive(Debug)]
pub struct FrameDecoder {
    header: [u8; HEADER_SIZE as usize],
    header_offset: usize,
    pending: Option<PendingFrame>,
}

#[derive(Debug)]
struct PendingFrame {
    frame_type: FrameType,
    flags: u16,
    stream_id: StreamId,
    payload: Vec<u8>,
    payload_offset: usize,
}

impl FrameDecoder {
    /// Creates a new decoder.
    #[inline]
    pub fn new() -> Self {
        Self {
            header: [0; HEADER_SIZE as usize],
            header_offset: 0,
            pending: None,
        }
    }

    /// Reads and validates a single frame from `reader`.
    ///
    /// # Return values
    ///
    /// - `Ok(Some(frame))` — a complete, valid frame was decoded.
    /// - `Ok(None)` — clean EOF; no more frames are available.
    /// - `Err(e)` — malformed frame, truncated data, or I/O error.
    pub async fn decode<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Frame>, ProtocolError> {
        // Header and payload progress live on the decoder rather than this
        // future so callers can safely use `decode` inside `tokio::select!`.
        // A losing branch may cancel the future after a partial socket read;
        // the next call must resume at that byte offset instead of treating
        // the rest of the frame as a new header.
        if self.pending.is_none() {
            while self.header_offset < HEADER_SIZE as usize {
                let n = match reader.read(&mut self.header[self.header_offset..]).await {
                    Ok(n) => n,
                    Err(error) => {
                        self.reset();
                        return Err(error.into());
                    }
                };
                if n == 0 {
                    if self.header_offset == 0 {
                        return Ok(None);
                    }
                    let got = self.header_offset;
                    self.reset();
                    return Err(ProtocolError::TruncatedHeader { got });
                }
                self.header_offset += n;
            }

            let magic = [
                self.header[0],
                self.header[1],
                self.header[2],
                self.header[3],
            ];
            if magic != MAGIC {
                self.reset();
                return Err(ProtocolError::InvalidMagic(magic));
            }

            let version = self.header[4];
            if version != VERSION {
                self.reset();
                return Err(ProtocolError::UnsupportedVersion(version));
            }

            let frame_type = match FrameType::from_raw(self.header[5]) {
                Some(frame_type) => frame_type,
                None => {
                    let raw = self.header[5];
                    self.reset();
                    return Err(ProtocolError::UnknownFrameType(raw));
                }
            };

            let flags = u16::from_be_bytes([self.header[6], self.header[7]]);
            if flags != 0 {
                self.reset();
                return Err(ProtocolError::UnsupportedFlags(flags));
            }

            let stream_id = StreamId(u32::from_be_bytes([
                self.header[8],
                self.header[9],
                self.header[10],
                self.header[11],
            ]));
            let payload_len = u32::from_be_bytes([
                self.header[12],
                self.header[13],
                self.header[14],
                self.header[15],
            ]);
            if payload_len > MAX_FRAME_PAYLOAD {
                self.reset();
                return Err(ProtocolError::FrameTooLarge(payload_len));
            }

            self.header_offset = 0;
            self.pending = Some(PendingFrame {
                frame_type,
                flags,
                stream_id,
                payload: vec![0; payload_len as usize],
                payload_offset: 0,
            });
        }

        let pending = self
            .pending
            .as_mut()
            .expect("a validated header creates a pending frame");
        while pending.payload_offset < pending.payload.len() {
            let n = match reader
                .read(&mut pending.payload[pending.payload_offset..])
                .await
            {
                Ok(n) => n,
                Err(error) => {
                    self.reset();
                    return Err(error.into());
                }
            };
            if n == 0 {
                let got = pending.payload_offset;
                let expected = pending.payload.len();
                self.reset();
                return Err(ProtocolError::TruncatedPayload { got, expected });
            }
            pending.payload_offset += n;
        }

        let pending = self
            .pending
            .take()
            .expect("payload completion retains its pending frame");
        Frame::new(
            pending.frame_type,
            pending.flags,
            pending.stream_id,
            pending.payload,
        )
        .map(Some)
    }

    fn reset(&mut self) {
        self.header_offset = 0;
        self.pending = None;
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;
    use tokio::io::duplex;
    use tokio::io::AsyncWriteExt;

    // --- Helpers ---
    async fn encode_frame_async(frame: &Frame) -> Vec<u8> {
        let mut buf = Vec::new();
        FrameEncoder::encode(&mut buf, frame).await.unwrap();
        buf
    }

    fn encode_frame(frame: &Frame) -> Vec<u8> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(encode_frame_async(frame))
    }

    async fn decode_bytes_async(bytes: &[u8]) -> Result<Option<Frame>, ProtocolError> {
        let (r, mut w) = duplex(4096);
        w.write_all(bytes).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        decoder.decode(&mut Box::pin(r)).await
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Option<Frame>, ProtocolError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(decode_bytes_async(bytes))
    }

    #[tokio::test]
    async fn decode_resumes_after_header_and_payload_cancellation() {
        let frame = Frame::stream(
            StreamId::new(7).unwrap(),
            FrameType::Data,
            b"cancellation-safe payload".to_vec(),
        )
        .unwrap();
        let wire = encode_frame_async(&frame).await;
        let (mut reader, mut writer) = duplex(4096);
        let mut decoder = FrameDecoder::new();

        writer.write_all(&wire[..7]).await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(25),
            decoder.decode(&mut reader),
        )
        .await
        .is_err());

        let payload_prefix = HEADER_SIZE as usize + 3;
        writer.write_all(&wire[7..payload_prefix]).await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(25),
            decoder.decode(&mut reader),
        )
        .await
        .is_err());

        writer.write_all(&wire[payload_prefix..]).await.unwrap();
        let decoded = decoder.decode(&mut reader).await.unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    // TEST 1 — Round trip: control frame.
    #[test]
    fn roundtrip_control_frame() {
        let frame = Frame::control(FrameType::Hello, b"agent-1 ready".to_vec()).unwrap();
        let wire = encode_frame(&frame);
        let decoded = decode_bytes(&wire).unwrap().unwrap();
        assert_eq!(decoded.frame_type, FrameType::Hello);
        assert_eq!(decoded.flags, 0);
        assert!(decoded.stream_id.is_control());
        assert_eq!(decoded.payload, b"agent-1 ready");
    }

    // TEST 1b — Round trip: stream frame.
    #[test]
    fn roundtrip_stream_frame() {
        let frame = Frame::stream(
            StreamId::new(5).unwrap(),
            FrameType::Data,
            b"\x00\xff binary".to_vec(),
        )
        .unwrap();
        let wire = encode_frame(&frame);
        let decoded = decode_bytes(&wire).unwrap().unwrap();
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id.get(), 5);
        assert_eq!(decoded.payload, b"\x00\xff binary");
    }

    // TEST 2 — Binary payload (non-UTF8).
    #[test]
    fn roundtrip_binary_payload() {
        let payload: Vec<u8> = (0..=255).collect();
        let frame =
            Frame::stream(StreamId::new(1).unwrap(), FrameType::Data, payload.clone()).unwrap();
        let wire = encode_frame(&frame);
        let decoded = decode_bytes(&wire).unwrap().unwrap();
        assert_eq!(decoded.payload, payload);
    }

    // TEST 3 — Fragmented header (1 byte per read).
    #[test]
    fn fragmented_header_1_byte_at_a_time() {
        let frame = Frame::control(FrameType::Ping, vec![]).unwrap();
        let wire = encode_frame(&frame);
        // Feed 1 byte at a time.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (r, mut w) = duplex(4096);
            // Write all at once into the writer side.
            w.write_all(&wire).await.unwrap();
            drop(w);
            let mut reader = Box::pin(r);
            let mut decoder = FrameDecoder::new();
            let decoded = decoder.decode(&mut reader).await.unwrap().unwrap();
            assert_eq!(decoded.frame_type, FrameType::Ping);
            assert_eq!(decoded.payload, b"");
        });
    }

    // TEST 4 — Fragmented payload (1 byte per read).
    #[test]
    fn fragmented_payload_1_byte_at_a_time() {
        let payload: Vec<u8> = (0..20).collect();
        let frame =
            Frame::stream(StreamId::new(1).unwrap(), FrameType::Data, payload.clone()).unwrap();
        let wire = encode_frame(&frame);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (r, mut w) = duplex(4096);
            w.write_all(&wire).await.unwrap();
            drop(w);
            let mut reader = Box::pin(r);
            let mut decoder = FrameDecoder::new();
            let decoded = decoder.decode(&mut reader).await.unwrap().unwrap();
            assert_eq!(decoded.payload, payload);
        });
    }

    // TEST 5 — Coalesced frames (two frames in one buffer).
    #[test]
    fn coalesced_frames() {
        let frame1 = Frame::control(FrameType::Hello, b"a".to_vec()).unwrap();
        let frame2 =
            Frame::stream(StreamId::new(3).unwrap(), FrameType::Data, b"bc".to_vec()).unwrap();
        let wire1 = encode_frame(&frame1);
        let wire2 = encode_frame(&frame2);
        let combined = [wire1.as_slice(), wire2.as_slice()].concat();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (r, mut w) = duplex(4096);
            w.write_all(&combined).await.unwrap();
            drop(w);
            let mut reader = Box::pin(r);
            let mut decoder = FrameDecoder::new();

            let decoded1 = decoder.decode(&mut reader).await.unwrap().unwrap();
            assert_eq!(decoded1.frame_type, FrameType::Hello);
            assert_eq!(decoded1.payload, b"a");

            let decoded2 = decoder.decode(&mut reader).await.unwrap().unwrap();
            assert_eq!(decoded2.frame_type, FrameType::Data);
            assert_eq!(decoded2.stream_id.get(), 3);
            assert_eq!(decoded2.payload, b"bc");

            // Clean EOF after last frame.
            let eof = decoder.decode(&mut reader).await.unwrap();
            assert!(eof.is_none());
        });
    }

    // TEST 6 — Clean EOF before next frame.
    #[tokio::test]
    async fn clean_eof() {
        let (r, w) = duplex(4096);
        drop(w); // Close writer immediately — no data sent.
        let mut decoder = FrameDecoder::new();
        let result = decoder.decode(&mut Box::pin(r)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // TEST 7 — Truncated header.
    #[tokio::test]
    async fn truncated_header() {
        let (r, mut w) = duplex(4096);
        w.write_all(&[0x54, 0x50, 0x58, 0x31, 0x01]).await.unwrap(); // 5 bytes of header.
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::TruncatedHeader { got: 5 }));
    }

    // TEST 8 — Truncated payload.
    #[tokio::test]
    async fn truncated_payload() {
        // Write a header declaring 10-byte payload, but send only 3 bytes.
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = FrameType::Data.as_u8();
        header[12] = 0;
        header[13] = 0;
        header[14] = 0;
        header[15] = 10; // 10-byte payload.
        let (r, mut w) = duplex(4096);
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 3]).await.unwrap(); // Only 3 bytes.
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::TruncatedPayload {
                got: 3,
                expected: 10
            }
        ));
    }

    // TEST 9 — Invalid magic.
    #[tokio::test]
    async fn invalid_magic() {
        let (r, mut w) = duplex(4096);
        let mut bad_header = [0u8; 16];
        bad_header[0..4].copy_from_slice(b"XXXX"); // Bad magic.
        bad_header[4] = VERSION;
        bad_header[5] = FrameType::Hello.as_u8();
        w.write_all(&bad_header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap(); // Empty payload.
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMagic(_)));
    }

    // TEST 10 — Unsupported version.
    #[tokio::test]
    async fn unsupported_version() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = 99; // Bad version.
        header[5] = FrameType::Hello.as_u8();
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::UnsupportedVersion(99)));
    }

    #[tokio::test]
    async fn protocol_v1_client_is_rejected_explicitly() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = 1;
        header[5] = FrameType::Hello.as_u8();
        w.write_all(&header).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::UnsupportedVersion(1)));
    }

    // TEST 11 — Unknown frame type.
    #[tokio::test]
    async fn unknown_frame_type() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = 0xCC; // Unknown frame type.
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::UnknownFrameType(0xCC)));
    }

    // TEST 12 — Unsupported flags.
    #[tokio::test]
    async fn unsupported_flags() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = FrameType::Hello.as_u8();
        header[6] = 0x00;
        header[7] = 0x01; // Non-zero flags.
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::UnsupportedFlags(0x0001)));
    }

    // TEST 13 — Invalid stream scope: DATA with stream_id == 0.
    #[tokio::test]
    async fn invalid_stream_scope_data_control() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = FrameType::Data.as_u8(); // Stream frame.
                                             // Stream ID = 0 (control).
        header[8] = 0;
        header[9] = 0;
        header[10] = 0;
        header[11] = 0;
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap(); // 0 payload.
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidStreamScope { .. }));
    }

    // TEST 13b — Invalid stream scope: PING with stream_id > 0.
    #[tokio::test]
    async fn invalid_stream_scope_ping_stream() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = FrameType::Ping.as_u8(); // Control frame.
                                             // Stream ID = 1 (should be 0).
        header[8] = 0;
        header[9] = 0;
        header[10] = 0;
        header[11] = 1;
        w.write_all(&header).await.unwrap();
        w.write_all(&[0u8; 4]).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidStreamScope { .. }));
    }

    // TEST 14 — Oversized frame on encode.
    #[tokio::test]
    async fn encode_rejects_oversized_payload() {
        let oversized_payload = vec![0u8; (MAX_FRAME_PAYLOAD + 1) as usize];
        // Frame::stream validates payload size and returns Err.
        let frame_result = Frame::stream(
            StreamId::new(1).unwrap(),
            FrameType::Data,
            oversized_payload,
        );
        assert!(frame_result.is_err());
        assert!(matches!(
            frame_result.unwrap_err(),
            ProtocolError::EncodeFrameTooLarge(_)
        ));
    }

    // TEST 15 — Oversized frame on decode (header announces oversized payload).
    #[tokio::test]
    async fn decode_rejects_oversized_announced_payload() {
        let (r, mut w) = duplex(4096);
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[5] = FrameType::Data.as_u8();
        // Announce 1 MiB payload (way over 64 KiB limit).
        header[12] = 0x00;
        header[13] = 0x10;
        header[14] = 0x00;
        header[15] = 0x00;
        w.write_all(&header).await.unwrap();
        drop(w);
        let mut decoder = FrameDecoder::new();
        let err = decoder.decode(&mut Box::pin(r)).await.unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge(0x0010_0000)));
    }

    // TEST 16 — Real loopback TCP frame test.
    #[tokio::test]
    async fn real_tcp_loopback_roundtrip() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;
        use tokio::net::TcpStream;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let frame = Frame::control(FrameType::Hello, b"hello from agent".to_vec()).unwrap();

        let server = async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut decoder = FrameDecoder::new();
            let decoded = decoder.decode(&mut socket).await.unwrap().unwrap();
            assert_eq!(decoded.frame_type, FrameType::Hello);
            assert_eq!(decoded.payload, b"hello from agent");

            // Respond with a REGISTERED frame.
            let response = Frame::control(FrameType::Registered, b"registered".to_vec()).unwrap();
            FrameEncoder::encode(&mut socket, &response).await.unwrap();
        };

        let client = async move {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            FrameEncoder::encode(&mut socket, &frame).await.unwrap();

            let mut decoder = FrameDecoder::new();
            let decoded = decoder.decode(&mut socket).await.unwrap().unwrap();
            assert_eq!(decoded.frame_type, FrameType::Registered);
            assert_eq!(decoded.payload, b"registered");
        };

        tokio::join!(server, client);
    }
}
