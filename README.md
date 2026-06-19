# wt-protocol

The Walkie Textie wire protocol: a small `no_std` Rust codec for the COBS-framed,
CRC-16 binary command/response protocol spoken between the phone app and the
ESP32 firmware over serial or BLE.

It is shared by both sides as a git submodule so they cannot drift:

- the firmware parses commands and serialises responses (`parse_command`,
  `encode_response`);
- the app serialises commands and parses responses (`encode_command`,
  `parse_response`).

## Wire format

Before COBS encoding, each frame is:

```
[version: u8][id: u8][length: u16 LE][payload: length bytes][crc16: u16 LE]
```

The CRC is CRC-16-XMODEM over `[version][id][length][payload]`. The whole frame is
then COBS-encoded with a trailing `0x00` delimiter.

| Direction | id | Meaning |
|-----------|------|---------|
| host -> device | 0x01 | GetVersion |
| host -> device | 0x03 | Reboot |
| host -> device | 0x10 | LoraTx (data) |
| device -> host | 0x01 | Version (major, minor, patch) |
| device -> host | 0x10 | TxComplete |
| device -> host | 0x11 | RxPacket (data, rssi i16 LE, snr i8) |
| device -> host | 0xFF | Error (status, original command id) |

## Use

```rust
use wt_protocol::{encode_command, parse_response, Command, FrameAccumulator, cobs_decode};

// App side: send a LoRa transmission.
let frame = encode_command(&Command::lora_tx(b"hello").unwrap());
// write `frame` to the transport

// App side: reassemble and decode replies from the byte stream.
let mut acc = FrameAccumulator::new();
for byte in incoming_bytes {
    if let Some(cobs) = acc.push(byte) {
        if let Ok(raw) = cobs_decode(&cobs) {
            if let Ok(response) = parse_response(&raw) { /* ... */ }
        }
    }
}
```

`no_std` by default; uses `heapless`, `corncobs` and `crc`.
