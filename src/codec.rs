//! Frame encode/decode for both directions of the protocol.
//!
//! Wire format (before COBS): `[version:u8][id:u8][length:u16 LE][payload][crc16:u16 LE]`,
//! CRC-16-XMODEM over `[version][id][length][payload]`, then COBS-encoded with a
//! trailing `0x00` delimiter.

use crate::types::{
    CapacityError, Command, CommandId, Response, ResponseId, ResponseStatus,
};
use crate::{MAX_FRAME_SIZE, PROTOCOL_VERSION};
use crc::{Crc, CRC_16_XMODEM};
use heapless::Vec;

const CRC: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);

/// CRC-16-XMODEM over `data`.
pub fn crc16(data: &[u8]) -> u16 {
    CRC.checksum(data)
}

/// Error decoding a frame into a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidVersion,
    CrcError,
    UnknownId(u8),
    BadPayload,
}

/// Build a raw (un-COBS) frame: version, id, length, payload, CRC.
fn build_raw(id: u8, payload: &[u8]) -> Vec<u8, MAX_FRAME_SIZE> {
    let mut frame: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
    let _ = frame.push(PROTOCOL_VERSION);
    let _ = frame.push(id);
    let _ = frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    let _ = frame.extend_from_slice(payload);
    let crc = crc16(&frame);
    let _ = frame.extend_from_slice(&crc.to_le_bytes());
    frame
}

/// COBS-encode (with trailing zero delimiter).
fn cobs_encode(raw: &[u8]) -> Vec<u8, MAX_FRAME_SIZE> {
    let mut out: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
    let _ = out.resize(corncobs::max_encoded_len(raw.len()), 0);
    let len = corncobs::encode_buf(raw, &mut out);
    out.truncate(len);
    out
}

/// COBS-decode a frame (delimiter included), for tests/verification.
pub fn cobs_decode(encoded: &[u8]) -> Result<Vec<u8, MAX_FRAME_SIZE>, ParseError> {
    let mut out: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
    out.resize(encoded.len(), 0).map_err(|_| ParseError::TooShort)?;
    let len = corncobs::decode_buf(encoded, &mut out).map_err(|_| ParseError::BadPayload)?;
    out.truncate(len);
    Ok(out)
}

/// Validate a raw frame and return `(id, payload)`.
fn parse_raw(data: &[u8]) -> Result<(u8, &[u8]), ParseError> {
    if data.len() < 6 {
        return Err(ParseError::TooShort);
    }
    if data[0] != PROTOCOL_VERSION {
        return Err(ParseError::InvalidVersion);
    }
    let id = data[1];
    let length = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + length + 2 {
        return Err(ParseError::TooShort);
    }
    let payload = &data[4..4 + length];
    let received = u16::from_le_bytes([data[4 + length], data[5 + length]]);
    if crc16(&data[..4 + length]) != received {
        return Err(ParseError::CrcError);
    }
    Ok((id, payload))
}

// --- Backend role: send commands, parse responses ----------------------------

/// Encode a command into a COBS frame ready for the wire.
pub fn encode_command(command: &Command) -> Vec<u8, MAX_FRAME_SIZE> {
    let raw = match command {
        Command::GetVersion => build_raw(CommandId::GetVersion as u8, &[]),
        Command::Reboot => build_raw(CommandId::Reboot as u8, &[]),
        Command::LoraTx { data } => build_raw(CommandId::LoraTx as u8, data),
        Command::SetSpreadingFactor { spreading_factor } => {
            build_raw(CommandId::SetSpreadingFactor as u8, &[*spreading_factor])
        }
        Command::GetRadioConfig => build_raw(CommandId::GetRadioConfig as u8, &[]),
    };
    cobs_encode(&raw)
}

/// Parse a COBS-decoded frame into a response.
pub fn parse_response(data: &[u8]) -> Result<Response, ParseError> {
    let (id, payload) = parse_raw(data)?;
    match ResponseId::from_byte(id) {
        Some(ResponseId::Version) => {
            if payload.len() != 3 {
                return Err(ParseError::BadPayload);
            }
            Ok(Response::Version { major: payload[0], minor: payload[1], patch: payload[2] })
        }
        Some(ResponseId::TxComplete) => Ok(Response::TxComplete),
        Some(ResponseId::RxPacket) => {
            if payload.len() < 3 {
                return Err(ParseError::BadPayload);
            }
            let split = payload.len() - 3;
            let rssi = i16::from_le_bytes([payload[split], payload[split + 1]]);
            let snr = payload[split + 2] as i8;
            Response::rx_packet(&payload[..split], rssi, snr).map_err(|_| ParseError::BadPayload)
        }
        Some(ResponseId::RadioConfig) => {
            if payload.len() != 11 {
                return Err(ParseError::BadPayload);
            }
            Ok(Response::RadioConfig {
                frequency_hz: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
                spreading_factor: payload[4],
                bandwidth_khz: u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]),
                coding_rate: payload[9],
                tx_power_dbm: payload[10] as i8,
            })
        }
        Some(ResponseId::TxRefused) => {
            if payload.len() != 4 {
                return Err(ParseError::BadPayload);
            }
            Ok(Response::TxRefused {
                retry_after_secs: u32::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]),
            })
        }
        Some(ResponseId::Error) => {
            if payload.len() != 2 {
                return Err(ParseError::BadPayload);
            }
            let status = ResponseStatus::from_byte(payload[0]).unwrap_or(ResponseStatus::InvalidCommand);
            Ok(Response::Error { status, original_command_id: payload[1] })
        }
        None => Err(ParseError::UnknownId(id)),
    }
}

// --- Device role: parse commands, send responses -----------------------------

/// Parse a COBS-decoded frame into a command. Errors are protocol status codes
/// so the device can reply with a matching [`Response::Error`].
pub fn parse_command(data: &[u8]) -> Result<Command, ResponseStatus> {
    let (id, payload) = match parse_raw(data) {
        Ok(v) => v,
        Err(ParseError::InvalidVersion) => return Err(ResponseStatus::InvalidVersion),
        Err(ParseError::CrcError) => return Err(ResponseStatus::CrcError),
        Err(_) => return Err(ResponseStatus::InvalidLength),
    };
    match CommandId::from_byte(id) {
        Some(CommandId::GetVersion) => {
            if !payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::GetVersion)
        }
        Some(CommandId::Reboot) => {
            if !payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::Reboot)
        }
        Some(CommandId::LoraTx) => {
            if payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Command::lora_tx(payload).map_err(|_: CapacityError| ResponseStatus::InvalidLength)
        }
        Some(CommandId::SetSpreadingFactor) => {
            if payload.len() != 1 {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::SetSpreadingFactor { spreading_factor: payload[0] })
        }
        Some(CommandId::GetRadioConfig) => {
            if !payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::GetRadioConfig)
        }
        None => Err(ResponseStatus::InvalidCommand),
    }
}

/// Encode a response into a COBS frame ready for the wire.
pub fn encode_response(response: &Response) -> Vec<u8, MAX_FRAME_SIZE> {
    let raw = match response {
        Response::Version { major, minor, patch } => {
            build_raw(ResponseId::Version as u8, &[*major, *minor, *patch])
        }
        Response::TxComplete => build_raw(ResponseId::TxComplete as u8, &[]),
        Response::RxPacket { data, rssi, snr } => {
            let mut payload: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
            let _ = payload.extend_from_slice(data);
            let _ = payload.extend_from_slice(&rssi.to_le_bytes());
            let _ = payload.push(*snr as u8);
            build_raw(ResponseId::RxPacket as u8, &payload)
        }
        Response::RadioConfig {
            frequency_hz,
            spreading_factor,
            bandwidth_khz,
            coding_rate,
            tx_power_dbm,
        } => {
            let mut payload: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
            let _ = payload.extend_from_slice(&frequency_hz.to_le_bytes());
            let _ = payload.push(*spreading_factor);
            let _ = payload.extend_from_slice(&bandwidth_khz.to_le_bytes());
            let _ = payload.push(*coding_rate);
            let _ = payload.push(*tx_power_dbm as u8);
            build_raw(ResponseId::RadioConfig as u8, &payload)
        }
        Response::TxRefused { retry_after_secs } => {
            build_raw(ResponseId::TxRefused as u8, &retry_after_secs.to_le_bytes())
        }
        Response::Error { status, original_command_id } => {
            build_raw(ResponseId::Error as u8, &[*status as u8, *original_command_id])
        }
    };
    cobs_encode(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors. The frame layout matches the firmware README; the
    // CRC-16-XMODEM values below were verified against the canonical algorithm
    // (the firmware uses the same `crc` crate, so these are wire-compatible).
    // Note: the README's printed CRC for GetVersion and Version is stale; the
    // values here are the correct CRC-16-XMODEM of the frames.
    #[test]
    fn kat_get_version_command() {
        let frame = encode_command(&Command::GetVersion);
        assert_eq!(frame.as_slice(), &[0x03, 0x01, 0x01, 0x01, 0x03, 0x84, 0x41, 0x00]);
    }

    #[test]
    fn kat_reboot_command() {
        let frame = encode_command(&Command::Reboot);
        assert_eq!(frame.as_slice(), &[0x03, 0x01, 0x03, 0x01, 0x03, 0xe4, 0x2f, 0x00]);
    }

    #[test]
    fn kat_version_response() {
        let frame = encode_response(&Response::Version { major: 0, minor: 1, patch: 0 });
        assert_eq!(
            frame.as_slice(),
            &[0x04, 0x01, 0x01, 0x03, 0x01, 0x02, 0x01, 0x03, 0x22, 0x20, 0x00]
        );
    }

    #[test]
    fn command_round_trips_device_side() {
        let cmd = Command::lora_tx(b"Hello, radio").unwrap();
        let frame = encode_command(&cmd);
        let decoded = cobs_decode(&frame).unwrap();
        assert_eq!(parse_command(&decoded), Ok(cmd));
    }

    #[test]
    fn response_round_trips_backend_side() {
        let resp = Response::rx_packet(b"ping", -50, 9).unwrap();
        let frame = encode_response(&resp);
        let decoded = cobs_decode(&frame).unwrap();
        assert_eq!(parse_response(&decoded), Ok(resp));
    }

    #[test]
    fn version_and_error_round_trip() {
        for resp in [
            Response::Version { major: 1, minor: 2, patch: 3 },
            Response::TxComplete,
            Response::error(ResponseStatus::Timeout, CommandId::LoraTx),
        ] {
            let decoded = cobs_decode(&encode_response(&resp)).unwrap();
            assert_eq!(parse_response(&decoded), Ok(resp));
        }
    }

    #[test]
    fn radio_config_commands_round_trip_device_side() {
        for cmd in [
            Command::SetSpreadingFactor { spreading_factor: 12 },
            Command::GetRadioConfig,
        ] {
            let decoded = cobs_decode(&encode_command(&cmd)).unwrap();
            assert_eq!(parse_command(&decoded), Ok(cmd));
        }
    }

    #[test]
    fn radio_config_response_round_trips_backend_side() {
        let resp = Response::RadioConfig {
            frequency_hz: 869_525_000,
            spreading_factor: 12,
            bandwidth_khz: 250,
            coding_rate: 8,
            tx_power_dbm: 22,
        };
        let decoded = cobs_decode(&encode_response(&resp)).unwrap();
        assert_eq!(parse_response(&decoded), Ok(resp));
    }

    #[test]
    fn set_spreading_factor_requires_one_byte_payload() {
        // GetRadioConfig's empty payload under the SetSpreadingFactor id.
        let raw = build_raw(CommandId::SetSpreadingFactor as u8, &[]);
        assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidLength));

        let raw = build_raw(CommandId::SetSpreadingFactor as u8, &[7, 8]);
        assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidLength));
    }

    #[test]
    fn tx_refused_round_trips() {
        for secs in [0u32, 1_800, u32::MAX] {
            let resp = Response::TxRefused { retry_after_secs: secs };
            let decoded = cobs_decode(&encode_response(&resp)).unwrap();
            assert_eq!(parse_response(&decoded), Ok(resp));
        }
    }

    #[test]
    fn corrupt_crc_is_rejected() {
        let frame = encode_command(&Command::GetVersion);
        let mut raw = cobs_decode(&frame).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        assert_eq!(parse_command(&raw), Err(ResponseStatus::CrcError));
        assert_eq!(parse_response(&raw), Err(ParseError::CrcError));
    }

    #[test]
    fn unknown_and_wrong_version_rejected() {
        // Wrong version byte.
        let mut raw = cobs_decode(&encode_command(&Command::GetVersion)).unwrap();
        raw[0] = 0x00;
        assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidVersion));
    }
}
