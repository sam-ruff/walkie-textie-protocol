//! Frame accumulator for the COBS-delimited byte stream.

use crate::{FRAME_DELIMITER, MAX_FRAME_SIZE};
use heapless::Vec;

/// Accumulates incoming bytes and extracts complete COBS frames (delimited by
/// `0x00`). Push bytes from the serial/BLE link; each returned `Vec` is a
/// COBS-encoded frame ready to hand to [`crate::cobs_decode`] then a parser.
pub struct FrameAccumulator {
    buffer: Vec<u8, MAX_FRAME_SIZE>,
}

impl FrameAccumulator {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Push a byte. Returns the completed COBS frame (including the trailing
    /// delimiter) when a delimiter is seen, otherwise `None`.
    pub fn push(&mut self, byte: u8) -> Option<Vec<u8, MAX_FRAME_SIZE>> {
        if byte == FRAME_DELIMITER {
            if self.buffer.is_empty() {
                return None;
            }
            let mut frame = core::mem::replace(&mut self.buffer, Vec::new());
            // corncobs::decode_buf expects the trailing delimiter.
            let _ = frame.push(FRAME_DELIMITER);
            return Some(frame);
        }
        if self.buffer.push(byte).is_err() {
            // Overflow: drop the partial frame.
            self.buffer.clear();
        }
        None
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FrameAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cobs_decode, encode_command, Command};

    #[test]
    fn accumulates_then_decodes_a_command() {
        let frame = encode_command(&Command::GetVersion);
        let mut acc = FrameAccumulator::new();
        let mut completed = None;
        // Feed every byte including the trailing delimiter.
        for &b in frame.iter() {
            if let Some(f) = acc.push(b) {
                completed = Some(f);
            }
        }
        let f = completed.expect("frame completed at delimiter");
        let raw = cobs_decode(&f).unwrap();
        assert_eq!(raw[1], crate::CommandId::GetVersion as u8);
    }

    #[test]
    fn leading_delimiter_ignored() {
        let mut acc = FrameAccumulator::new();
        assert!(acc.push(FRAME_DELIMITER).is_none());
        assert!(acc.is_empty());
    }
}
