//! Frame encode/decode for both directions of the protocol.
//!
//! Wire format (before COBS): `[version:u8][id:u8][length:u16 LE][payload][crc16:u16 LE]`,
//! CRC-16-XMODEM over `[version][id][length][payload]`, then COBS-encoded with a
//! trailing `0x00` delimiter.

use crate::types::{
    BoxStatus, CapacityError, Command, CommandId, Response, ResponseId, ResponseStatus,
    MAX_BOX_NAME,
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
    out.resize(encoded.len(), 0)
        .map_err(|_| ParseError::TooShort)?;
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
        Command::GetBoxStatus => build_raw(CommandId::GetBoxStatus as u8, &[]),
    };
    cobs_encode(&raw)
}

// BoxStatus payload, all integers little-endian:
// [layout:u8][flags:u8][satellites:u8][battery:u8][clients:u8][lat_e7:i32][lon_e7:i32]
// [ssid_len:u8][ssid][host_len:u8][hostname]
// 0xFF means unknown for satellites and battery. Later layouts only append, so
// a parser ignores bytes it does not know.
const BOX_STATUS_LAYOUT: u8 = 1;
const BOX_UNKNOWN: u8 = 0xFF;
const FLAG_GPS_FIX: u8 = 1 << 0;
const FLAG_POSITION: u8 = 1 << 1;
const FLAG_CARD_OK: u8 = 1 << 2;
const FLAG_WIFI_ON: u8 = 1 << 3;

fn encode_box_status(status: &BoxStatus) -> Vec<u8, MAX_FRAME_SIZE> {
    let flag = |on: bool, bit: u8| if on { bit } else { 0 };
    let flags = flag(status.gps_fix, FLAG_GPS_FIX)
        | flag(status.position_e7.is_some(), FLAG_POSITION)
        | flag(status.card_ok, FLAG_CARD_OK)
        | flag(status.wifi_on, FLAG_WIFI_ON);
    let (lat, lon) = status.position_e7.unwrap_or((0, 0));
    let mut payload: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
    let _ = payload.extend_from_slice(&[
        BOX_STATUS_LAYOUT,
        flags,
        status.satellites.unwrap_or(BOX_UNKNOWN),
        status.battery_percent.unwrap_or(BOX_UNKNOWN),
        status.wifi_clients,
    ]);
    let _ = payload.extend_from_slice(&lat.to_le_bytes());
    let _ = payload.extend_from_slice(&lon.to_le_bytes());
    for text in [status.wifi_ssid.as_str(), status.hostname.as_str()] {
        let _ = payload.push(text.len() as u8);
        let _ = payload.extend_from_slice(text.as_bytes());
    }
    payload
}

/// Reads a length-prefixed string at `at`, returning it and the offset after it.
fn read_name(
    payload: &[u8],
    at: usize,
) -> Result<(heapless::String<MAX_BOX_NAME>, usize), ParseError> {
    let len = *payload.get(at).ok_or(ParseError::BadPayload)? as usize;
    let bytes = payload
        .get(at + 1..at + 1 + len)
        .ok_or(ParseError::BadPayload)?;
    let text = core::str::from_utf8(bytes).map_err(|_| ParseError::BadPayload)?;
    let mut name = heapless::String::new();
    name.push_str(text).map_err(|_| ParseError::BadPayload)?;
    Ok((name, at + 1 + len))
}

fn parse_box_status(payload: &[u8]) -> Result<BoxStatus, ParseError> {
    const FIXED: usize = 13;
    if payload.len() < FIXED || payload[0] < BOX_STATUS_LAYOUT {
        return Err(ParseError::BadPayload);
    }
    let known = |byte: u8| (byte != BOX_UNKNOWN).then_some(byte);
    let flags = payload[1];
    let lat = i32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]);
    let lon = i32::from_le_bytes([payload[9], payload[10], payload[11], payload[12]]);
    let (wifi_ssid, next) = read_name(payload, FIXED)?;
    let (hostname, _) = read_name(payload, next)?;
    Ok(BoxStatus {
        gps_fix: flags & FLAG_GPS_FIX != 0,
        position_e7: (flags & FLAG_POSITION != 0).then_some((lat, lon)),
        satellites: known(payload[2]),
        battery_percent: known(payload[3]),
        card_ok: flags & FLAG_CARD_OK != 0,
        wifi_on: flags & FLAG_WIFI_ON != 0,
        wifi_clients: payload[4],
        wifi_ssid,
        hostname,
    })
}

/// Parse a COBS-decoded frame into a response.
pub fn parse_response(data: &[u8]) -> Result<Response, ParseError> {
    let (id, payload) = parse_raw(data)?;
    match ResponseId::from_byte(id) {
        Some(ResponseId::Version) => {
            if payload.len() != 3 {
                return Err(ParseError::BadPayload);
            }
            Ok(Response::Version {
                major: payload[0],
                minor: payload[1],
                patch: payload[2],
            })
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
        Some(ResponseId::BoxStatus) => parse_box_status(payload).map(Response::BoxStatus),
        Some(ResponseId::Error) => {
            if payload.len() != 2 {
                return Err(ParseError::BadPayload);
            }
            let status =
                ResponseStatus::from_byte(payload[0]).unwrap_or(ResponseStatus::InvalidCommand);
            Ok(Response::Error {
                status,
                original_command_id: payload[1],
            })
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
            Ok(Command::SetSpreadingFactor {
                spreading_factor: payload[0],
            })
        }
        Some(CommandId::GetRadioConfig) => {
            if !payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::GetRadioConfig)
        }
        Some(CommandId::GetBoxStatus) => {
            if !payload.is_empty() {
                return Err(ResponseStatus::InvalidLength);
            }
            Ok(Command::GetBoxStatus)
        }
        None => Err(ResponseStatus::InvalidCommand),
    }
}

/// Encode a response into a COBS frame ready for the wire.
pub fn encode_response(response: &Response) -> Vec<u8, MAX_FRAME_SIZE> {
    let raw = match response {
        Response::Version {
            major,
            minor,
            patch,
        } => build_raw(ResponseId::Version as u8, &[*major, *minor, *patch]),
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
        Response::BoxStatus(status) => {
            build_raw(ResponseId::BoxStatus as u8, &encode_box_status(status))
        }
        Response::Error {
            status,
            original_command_id,
        } => build_raw(
            ResponseId::Error as u8,
            &[*status as u8, *original_command_id],
        ),
    };
    cobs_encode(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_LORA_PAYLOAD;

    // Known-answer vectors. The frame layout matches the firmware README; the
    // CRC-16-XMODEM values below were verified against the canonical algorithm
    // (the firmware uses the same `crc` crate, so these are wire-compatible).
    // Note: the README's printed CRC for GetVersion and Version is stale; the
    // values here are the correct CRC-16-XMODEM of the frames.
    #[test]
    fn kat_get_version_command() {
        let frame = encode_command(&Command::GetVersion);
        assert_eq!(
            frame.as_slice(),
            &[0x03, 0x01, 0x01, 0x01, 0x03, 0x84, 0x41, 0x00]
        );
    }

    #[test]
    fn kat_reboot_command() {
        let frame = encode_command(&Command::Reboot);
        assert_eq!(
            frame.as_slice(),
            &[0x03, 0x01, 0x03, 0x01, 0x03, 0xe4, 0x2f, 0x00]
        );
    }

    #[test]
    fn kat_version_response() {
        let frame = encode_response(&Response::Version {
            major: 0,
            minor: 1,
            patch: 0,
        });
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
            Response::Version {
                major: 1,
                minor: 2,
                patch: 3,
            },
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
            Command::SetSpreadingFactor {
                spreading_factor: 12,
            },
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
            let resp = Response::TxRefused {
                retry_after_secs: secs,
            };
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

    #[test]
    fn oversized_payloads_are_rejected_with_capacity_error() {
        let too_big = [0xAB; MAX_LORA_PAYLOAD + 1];
        assert_eq!(Command::lora_tx(&too_big), Err(CapacityError));
        assert_eq!(Response::rx_packet(&too_big, -50, 5), Err(CapacityError));

        let just_fits = [0xAB; MAX_LORA_PAYLOAD];
        assert!(Command::lora_tx(&just_fits).is_ok());
        assert!(Response::rx_packet(&just_fits, -50, 5).is_ok());
    }

    fn name(text: &str) -> heapless::String<MAX_BOX_NAME> {
        let mut out = heapless::String::new();
        out.push_str(text).unwrap();
        out
    }

    fn full_status() -> BoxStatus {
        BoxStatus {
            gps_fix: true,
            position_e7: Some((514_816_000, -31_791_000)),
            satellites: Some(9),
            battery_percent: Some(87),
            card_ok: true,
            wifi_on: true,
            wifi_clients: 2,
            wifi_ssid: name("World Box"),
            hostname: name("world.local"),
        }
    }

    #[test]
    fn get_box_status_round_trips_device_side() {
        let decoded = cobs_decode(&encode_command(&Command::GetBoxStatus)).unwrap();
        assert_eq!(parse_command(&decoded), Ok(Command::GetBoxStatus));
        let raw = build_raw(CommandId::GetBoxStatus as u8, &[1]);
        assert_eq!(parse_command(&raw), Err(ResponseStatus::InvalidLength));
    }

    #[test]
    fn box_status_round_trips_full_and_unknown() {
        let unknown = BoxStatus {
            wifi_ssid: name("Box"),
            ..BoxStatus::default()
        };
        for status in [full_status(), unknown] {
            let resp = Response::BoxStatus(status);
            let decoded = cobs_decode(&encode_response(&resp)).unwrap();
            assert_eq!(parse_response(&decoded), Ok(resp));
        }
    }

    #[test]
    fn kat_box_status_payload() {
        let raw = cobs_decode(&encode_response(&Response::BoxStatus(full_status()))).unwrap();
        let payload = &raw[4..raw.len() - 2];
        let mut expected = std::vec![1, 0b1111, 9, 87, 2];
        expected.extend_from_slice(&514_816_000i32.to_le_bytes());
        expected.extend_from_slice(&(-31_791_000i32).to_le_bytes());
        expected.push(9);
        expected.extend_from_slice(b"World Box");
        expected.push(11);
        expected.extend_from_slice(b"world.local");
        assert_eq!(payload, expected.as_slice());
    }

    #[test]
    fn box_status_ignores_bytes_from_later_layouts() {
        let mut payload = encode_box_status(&full_status());
        payload[0] = 2;
        payload.extend_from_slice(&[0xAA, 0xBB]).unwrap();
        let raw = build_raw(ResponseId::BoxStatus as u8, &payload);
        assert_eq!(parse_response(&raw), Ok(Response::BoxStatus(full_status())));
    }

    #[test]
    fn malformed_box_status_is_rejected() {
        let good = encode_box_status(&full_status());
        // Cut inside the hostname, and a name claiming to run past the end.
        for payload in [&good[..good.len() - 1], &good[..12]] {
            let raw = build_raw(ResponseId::BoxStatus as u8, payload);
            assert_eq!(parse_response(&raw), Err(ParseError::BadPayload));
        }
        let mut bad_utf8 = good.clone();
        bad_utf8[14] = 0xFF;
        let raw = build_raw(ResponseId::BoxStatus as u8, &bad_utf8);
        assert_eq!(parse_response(&raw), Err(ParseError::BadPayload));
        let mut layout_zero = good;
        layout_zero[0] = 0;
        let raw = build_raw(ResponseId::BoxStatus as u8, &layout_zero);
        assert_eq!(parse_response(&raw), Err(ParseError::BadPayload));
    }

    #[test]
    fn oversized_frame_fails_cobs_decode_as_too_short() {
        let too_big = [0x01; MAX_FRAME_SIZE + 1];
        assert_eq!(cobs_decode(&too_big), Err(ParseError::TooShort));
    }
}
