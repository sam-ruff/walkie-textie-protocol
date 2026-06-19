//! Command and response types for the binary protocol.

use crate::MAX_LORA_PAYLOAD;
use heapless::Vec;

/// Command IDs (host -> device).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandId {
    /// Get firmware version.
    GetVersion = 0x01,
    /// Reboot the device.
    Reboot = 0x03,
    /// Transmit data over LoRa.
    LoraTx = 0x10,
}

impl CommandId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::GetVersion),
            0x03 => Some(Self::Reboot),
            0x10 => Some(Self::LoraTx),
            _ => None,
        }
    }
}

/// Response IDs (device -> host).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseId {
    Version = 0x01,
    TxComplete = 0x10,
    RxPacket = 0x11,
    Error = 0xFF,
}

impl ResponseId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Version),
            0x10 => Some(Self::TxComplete),
            0x11 => Some(Self::RxPacket),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

/// A command parsed from (or to be sent over) the wire.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // Boxing not available in no_std
pub enum Command {
    GetVersion,
    Reboot,
    LoraTx { data: Vec<u8, MAX_LORA_PAYLOAD> },
}

impl Command {
    /// The command id for this command.
    pub fn id(&self) -> CommandId {
        match self {
            Command::GetVersion => CommandId::GetVersion,
            Command::Reboot => CommandId::Reboot,
            Command::LoraTx { .. } => CommandId::LoraTx,
        }
    }

    /// Build a `LoraTx` command from a byte slice. Errors if `data` exceeds
    /// [`MAX_LORA_PAYLOAD`].
    pub fn lora_tx(data: &[u8]) -> Result<Self, CapacityError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(data).map_err(|_| CapacityError)?;
        Ok(Command::LoraTx { data: buf })
    }
}

/// Status codes used in [`Response::Error`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidLength = 0x02,
    CrcError = 0x03,
    InvalidVersion = 0x04,
    LoraError = 0x10,
    Timeout = 0x11,
}

impl ResponseStatus {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::InvalidCommand),
            0x02 => Some(Self::InvalidLength),
            0x03 => Some(Self::CrcError),
            0x04 => Some(Self::InvalidVersion),
            0x10 => Some(Self::LoraError),
            0x11 => Some(Self::Timeout),
            _ => None,
        }
    }
}

/// A response parsed from (or to be sent over) the wire.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // Boxing not available in no_std
pub enum Response {
    /// Firmware version.
    Version { major: u8, minor: u8, patch: u8 },
    /// LoRa transmit completed.
    TxComplete,
    /// Received LoRa packet (unsolicited), with signal stats.
    RxPacket {
        data: Vec<u8, MAX_LORA_PAYLOAD>,
        rssi: i16,
        snr: i8,
    },
    /// Error with a status code and the originating command id.
    Error {
        status: ResponseStatus,
        original_command_id: u8,
    },
}

impl Response {
    pub fn error(status: ResponseStatus, command_id: CommandId) -> Self {
        Self::Error { status, original_command_id: command_id as u8 }
    }

    pub fn error_raw(status: ResponseStatus, original_command_id: u8) -> Self {
        Self::Error { status, original_command_id }
    }

    /// Build an `RxPacket` response from a byte slice. Errors if `data` exceeds
    /// [`MAX_LORA_PAYLOAD`].
    pub fn rx_packet(data: &[u8], rssi: i16, snr: i8) -> Result<Self, CapacityError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(data).map_err(|_| CapacityError)?;
        Ok(Response::RxPacket { data: buf, rssi, snr })
    }
}

/// A payload exceeded [`MAX_LORA_PAYLOAD`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityError;
