//! Walkie Textie wire protocol.
//!
//! A small, `no_std` codec for the COBS-framed, CRC-16 binary protocol spoken
//! between the phone app and the ESP32 firmware over serial or BLE. It is shared
//! by both sides so they cannot drift:
//!
//! * the firmware parses [`Command`]s and serialises [`Response`]s
//!   ([`parse_command`], [`encode_response`]);
//! * the app serialises [`Command`]s and parses [`Response`]s
//!   ([`encode_command`], [`parse_response`]).
//!
//! Wire format (before COBS):
//! `[version:u8][id:u8][length:u16 LE][payload][crc16:u16 LE]`, CRC-16-XMODEM,
//! then COBS-encoded with a trailing `0x00` delimiter.
#![cfg_attr(not(test), no_std)]

pub mod codec;
pub mod framing;
pub mod types;

/// Frame delimiter byte.
pub const FRAME_DELIMITER: u8 = 0x00;
/// Maximum encoded frame size.
pub const MAX_FRAME_SIZE: usize = 512;
/// Maximum LoRa payload carried in one command/response.
pub const MAX_LORA_PAYLOAD: usize = 256;
/// Protocol version byte.
pub const PROTOCOL_VERSION: u8 = 1;

pub use codec::{
    cobs_decode, crc16, encode_command, encode_response, parse_command, parse_response, ParseError,
};
pub use framing::FrameAccumulator;
pub use types::{
    CapacityError, Command, CommandId, Response, ResponseId, ResponseStatus,
};
