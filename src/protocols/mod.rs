use rand::Rng;
use rand::seq::SliceRandom;
use super::{CanFrame, mutate};

// ──────────────────────────────────────────────
// CAN raw frame generation
// ──────────────────────────────────────────────

/// Generate a random raw CAN 2.0A frame (11-bit ID).
pub fn can_random(rng: &mut impl Rng) -> CanFrame {
    CanFrame::random(rng)
}

/// Generate a CAN-FD frame (29-bit extended ID, up to 64 bytes).
pub fn canfd_random(rng: &mut impl Rng) -> CanFrame {
    let arb_id: u32 = rng.gen_range(0..0x1FFF_FFFF);
    let len: usize = rng.gen_range(1..=64);
    let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    CanFrame { arb_id, extended: true, data }
}

// ──────────────────────────────────────────────
// UDS (ISO 14229) frame builders
// ──────────────────────────────────────────────

pub const UDS_SERVICES: &[u8] = &[
    0x10, // DiagnosticSessionControl
    0x11, // ECUReset
    0x14, // ClearDiagnosticInformation
    0x19, // ReadDTCInformation
    0x22, // ReadDataByIdentifier
    0x23, // ReadMemoryByAddress
    0x27, // SecurityAccess
    0x28, // CommunicationControl
    0x2A, // ReadDataByPeriodicIdentifier
    0x2C, // DynamicallyDefineDataIdentifier
    0x2E, // WriteDataByIdentifier
    0x2F, // InputOutputControlByIdentifier
    0x31, // RoutineControl
    0x34, // RequestDownload
    0x35, // RequestUpload
    0x36, // TransferData
    0x37, // RequestTransferExit
    0x3D, // WriteMemoryByAddress
    0x3E, // TesterPresent
    0x85, // ControlDTCSetting
    0x86, // ResponseOnEvent
    0x87, // LinkControl
];

/// Build a UDS request frame for the given target ECU arbitration ID.
pub fn uds_request(target: u32, rng: &mut impl Rng) -> CanFrame {
    let service = *UDS_SERVICES.choose(rng).unwrap();
    let mut data = vec![service];
    // Add sub-function / DID / address bytes
    let extra = rng.gen_range(0..=6usize);
    for _ in 0..extra {
        data.push(rng.gen());
    }
    // ISO TP single frame: first byte = length
    let len = data.len() as u8;
    let mut frame_data = vec![len];
    frame_data.extend_from_slice(&data);
    frame_data.truncate(8);
    CanFrame::new(target, frame_data)
}

/// Security access level 1 seed request (service 0x27 subfunction 0x01).
pub fn uds_security_access_seed(target: u32) -> CanFrame {
    CanFrame::new(target, vec![0x02, 0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
}

/// Mutate an existing UDS frame.
pub fn uds_mutate(frame: &CanFrame, rng: &mut impl Rng) -> CanFrame {
    CanFrame::new(frame.arb_id, mutate(&frame.data, rng))
}

// ──────────────────────────────────────────────
// OBD-II (ISO 15031) frame builders
// ──────────────────────────────────────────────

pub const OBD_MODES: &[u8] = &[
    0x01, // Current data
    0x02, // Freeze frame
    0x03, // Stored DTCs
    0x04, // Clear DTCs
    0x05, // O2 sensor monitoring (legacy)
    0x06, // On-board monitoring results
    0x07, // Pending DTCs
    0x08, // Control on-board system
    0x09, // Vehicle info
    0x0A, // Permanent DTCs
];

/// Generate a random OBD-II request on the functional address 0x7DF.
pub fn obd_request(rng: &mut impl Rng) -> CanFrame {
    let mode = *OBD_MODES.choose(rng).unwrap();
    let pid: u8 = rng.gen();
    CanFrame::new(0x7DF, vec![0x02, mode, pid, 0x00, 0x00, 0x00, 0x00, 0x00])
}

// ──────────────────────────────────────────────
// DoIP (ISO 13400) payload builders (UDP/TCP)
// ──────────────────────────────────────────────

pub const DOIP_PAYLOAD_TYPES: &[u16] = &[
    0x0001, // Vehicle identification request
    0x0002, // Vehicle identification request with EID
    0x0003, // Vehicle identification request with VIN
    0x0004, // Vehicle announcement
    0x0005, // Routing activation request
    0x0006, // Routing activation response
    0x0007, // Alive check request
    0x0008, // Alive check response
    0x4001, // Diagnostic message
    0x4002, // Diagnostic message positive ack
    0x4003, // Diagnostic message negative ack
    0x0501, // Entity status request
    0x0502, // Entity status response
];

/// Build a raw DoIP frame as bytes (generic header + fuzzed payload).
pub fn doip_frame(rng: &mut impl Rng) -> Vec<u8> {
    let payload_type = *DOIP_PAYLOAD_TYPES.choose(rng).unwrap();
    let payload_len = rng.gen_range(0u32..=64);
    let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
    let mut frame = vec![
        0x02, // Protocol version
        0xFD, // Inverse protocol version
        ((payload_type >> 8) & 0xFF) as u8,
        (payload_type & 0xFF) as u8,
        ((payload_len >> 24) & 0xFF) as u8,
        ((payload_len >> 16) & 0xFF) as u8,
        ((payload_len >> 8) & 0xFF) as u8,
        (payload_len & 0xFF) as u8,
    ];
    frame.extend_from_slice(&payload);
    frame
}

// ──────────────────────────────────────────────
// J1939 (SAE heavy-duty) frame builders
// ──────────────────────────────────────────────

/// Generate a random J1939 frame (29-bit PGN-based ID).
pub fn j1939_random(rng: &mut impl Rng) -> CanFrame {
    let priority: u32 = rng.gen_range(0u32..8) << 26;
    let pgn: u32 = rng.gen_range(0u32..0xFFFF) << 8;
    let sa: u32 = rng.gen_range(0u32..0xFF);
    let arb_id = priority | pgn | sa;
    let len = rng.gen_range(1..=8);
    let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    CanFrame { arb_id, extended: true, data }
}


