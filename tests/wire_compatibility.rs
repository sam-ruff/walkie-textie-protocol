//! Wire and capacity regressions for the CRC, COBS and heapless dependencies.
use wt_protocol::{
    cobs_decode, crc16, encode_command, encode_response, parse_command, parse_response, Command,
    FrameAccumulator, ParseError, Response, ResponseStatus, MAX_FRAME_SIZE, MAX_LORA_PAYLOAD,
    PROTOCOL_VERSION,
};

#[test]
fn crc_xmodem_canonical_vectors() {
    assert_eq!(crc16(b"123456789"), 0x31c3);
    assert_eq!(crc16(b""), 0);
}

#[test]
fn full_cobs_block_keeps_the_known_wire_encoding() {
    // 254 nonzero payload bytes occupy one full COBS block. The CRC (0x1947)
    // was computed independently with the bitwise XMODEM polynomial 0x1021.
    let command = Command::lora_tx(&[0xab; 254]).unwrap();
    let mut expected = vec![0x04, 0x01, 0x10, 0xfe, 0xff];
    expected.extend_from_slice(&[0xab; 254]);
    expected.extend_from_slice(&[0x03, 0x47, 0x19, 0x00]);
    assert_eq!(encode_command(&command).as_slice(), expected);
    assert_eq!(parse_command(&cobs_decode(&expected).unwrap()), Ok(command));
}

#[test]
fn commands_keep_capacity_and_cobs_boundary_payloads() {
    for length in [1, 253, 254, 255, MAX_LORA_PAYLOAD] {
        for byte in [0, 0xab, 0xff] {
            let payload = vec![byte; length];
            let command = Command::lora_tx(&payload).unwrap();
            let frame = encode_command(&command);
            assert_eq!(frame.last(), Some(&0));
            assert!(!frame[..frame.len() - 1].contains(&0));
            let raw = cobs_decode(&frame).unwrap();
            assert_eq!(&raw[2..4], &(length as u16).to_le_bytes());
            assert_eq!(&raw[4..4 + length], payload);
            assert_eq!(raw.len(), length + 6);
            assert_eq!(parse_command(&raw), Ok(command));
        }
    }
}

#[test]
fn maximum_rx_packets_preserve_signed_signal_stats() {
    let payload: Vec<u8> = (0..=255).collect();
    for (rssi, snr) in [(i16::MIN, i8::MIN), (i16::MAX, i8::MAX)] {
        let response = Response::rx_packet(&payload, rssi, snr).unwrap();
        let raw = cobs_decode(&encode_response(&response)).unwrap();
        assert_eq!(raw.len(), MAX_LORA_PAYLOAD + 9);
        assert_eq!(&raw[2..4], &259u16.to_le_bytes());
        assert_eq!(&raw[4..260], payload);
        assert_eq!(&raw[260..262], &rssi.to_le_bytes());
        assert_eq!(raw[262], snr as u8);
        assert_eq!(parse_response(&raw), Ok(response));
    }
}

#[test]
fn truncated_cobs_returns_an_error_without_panicking() {
    for bytes in [&[][..], &[1][..], &[3, 1][..], &[0xff, 1, 0][..]] {
        assert_eq!(cobs_decode(bytes), Err(ParseError::BadPayload));
    }
    let frame = encode_command(&Command::GetVersion);
    assert_eq!(
        cobs_decode(&frame[..frame.len() - 1]),
        Err(ParseError::BadPayload)
    );
}

#[test]
fn stream_delimiters_preserve_consecutive_maximum_frames() {
    let mut accumulator = FrameAccumulator::new();
    for byte in [0, 0xff] {
        let command = Command::lora_tx(&[byte; MAX_LORA_PAYLOAD]).unwrap();
        let frame = encode_command(&command);
        assert!(accumulator.push(0).is_none());
        for &value in &frame[..frame.len() - 1] {
            assert!(accumulator.push(value).is_none());
        }
        let received = accumulator.push(0).unwrap();
        assert_eq!(received, frame);
        assert_eq!(parse_command(&cobs_decode(&received).unwrap()), Ok(command));
        assert!(accumulator.is_empty());
    }
}

#[test]
fn unknown_ids_are_rejected_in_both_directions() {
    // A valid CRC under an id neither side defines.
    let mut raw = cobs_decode(&encode_command(&Command::GetVersion)).unwrap();
    raw[1] = 0x7e;
    let crc = crc16(&raw[..4]).to_le_bytes();
    raw[4..6].copy_from_slice(&crc);
    assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidCommand));
    assert_eq!(parse_response(&raw), Err(ParseError::UnknownId(0x7e)));
}

#[test]
fn accumulator_recovers_after_an_oversized_frame() {
    let mut accumulator = FrameAccumulator::new();
    for _ in 0..MAX_FRAME_SIZE + 10 {
        assert!(accumulator.push(0xab).is_none());
    }
    assert!(accumulator.len() < MAX_FRAME_SIZE);
    // The overflowed tail surfaces as a frame that fails to decode cleanly.
    let junk = accumulator.push(0).unwrap();
    assert!(cobs_decode(&junk).map_or(true, |raw| parse_command(&raw).is_err()));
    let frame = encode_command(&Command::GetVersion);
    let received = frame.iter().find_map(|&byte| accumulator.push(byte));
    assert_eq!(received.as_deref(), Some(frame.as_slice()));
}

/// Build a CRC-valid raw frame by hand so payloads beyond the codec's own
/// capacity checks reach the parsers.
fn raw_frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![PROTOCOL_VERSION, id];
    raw.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    raw.extend_from_slice(payload);
    let crc = crc16(&raw).to_le_bytes();
    raw.extend_from_slice(&crc);
    raw
}

#[test]
fn over_capacity_payloads_in_valid_frames_are_rejected_cleanly() {
    // heapless 0.9.4 reworked `Vec::extend_from_slice` overflow handling; a
    // payload one byte past capacity must still fail instead of truncating.
    for length in [MAX_LORA_PAYLOAD + 1, MAX_FRAME_SIZE - 6] {
        let payload = vec![0xab; length];
        let command = raw_frame(0x10, &payload);
        assert_eq!(parse_command(&command), Err(ResponseStatus::InvalidLength));
        let mut rx = payload.clone();
        rx.extend_from_slice(&[0x9c, 0xff, 0xf6]);
        let response = raw_frame(0x11, &rx);
        assert_eq!(parse_response(&response), Err(ParseError::BadPayload));
    }
    let fits = raw_frame(0x10, &[0xab; MAX_LORA_PAYLOAD]);
    assert_eq!(
        parse_command(&fits),
        Command::lora_tx(&[0xab; MAX_LORA_PAYLOAD]).map_err(|_| ResponseStatus::InvalidLength)
    );
}

#[test]
fn declared_length_beyond_the_frame_is_too_short() {
    let mut raw = raw_frame(0x10, b"hi");
    raw[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidLength));
    assert_eq!(parse_response(&raw), Err(ParseError::TooShort));
}
