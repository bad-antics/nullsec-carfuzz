<div align="center">

# 🏎️ NullSec CarFuzz

### Automotive Protocol Fuzzer

[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()
[![NullSec](https://img.shields.io/badge/NullSec-Linux_v5.0-00ff41?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/bad-antics/nullsec-linux)

*Intelligent fuzzing for CAN, UDS, OBD-II, and DoIP automotive protocols*

</div>

---

## 🎯 Overview

NullSec CarFuzz is a coverage-guided fuzzer specifically designed for automotive protocols. It understands protocol grammars for CAN, UDS (ISO 14229), OBD-II (ISO 15031), and DoIP (ISO 13400), generating intelligent test cases that explore deep protocol states rather than random data.

## ⚡ Features

| Feature | Description |
|---------|-------------|
| **Grammar-Aware Fuzzing** | Protocol-aware mutation for CAN, UDS, OBD-II, DoIP |
| **Coverage Tracking** | Monitor ECU responses to guide mutation strategy |
| **State Machine** | Track protocol state to reach deep execution paths |
| **Crash Detection** | Detect ECU resets, hangs, and error responses |
| **Session Manager** | Handle diagnostic session changes and security access |
| **Report Generator** | Detailed crash reports with reproduction steps |

## 📋 Supported Protocols

| Protocol | Standard | Fuzzing Depth |
|----------|----------|---------------|
| CAN 2.0A/B | ISO 11898 | Frame-level |
| UDS | ISO 14229 | Service + sub-function |
| OBD-II | ISO 15031 | PID + mode |
| DoIP | ISO 13400 | Full TCP/UDP stack |
| XCP | ASAM | Partial |
| KWP2000 | ISO 14230 | Service-level |

## 🚀 Quick Start

```bash
# Fuzz UDS services on an ECU
nullsec-carfuzz uds --interface can0 --target 0x7E0 --services all

# Fuzz OBD-II PIDs
nullsec-carfuzz obd --interface can0 --modes 01,09 --timeout 100ms

# Grammar-guided CAN fuzzing
nullsec-carfuzz can --interface can0 --id-range 0x600-0x6FF --duration 1h

# Generate crash report
nullsec-carfuzz report --input crashes/ -o report.html
```

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [nullsec-canbus](https://github.com/bad-antics/nullsec-canbus) | CAN bus sniffing & injection |
| [nullsec-keyfob](https://github.com/bad-antics/nullsec-keyfob) | Key fob & immobilizer analysis |
| [nullsec-sdr](https://github.com/bad-antics/nullsec-sdr) | Software-defined radio toolkit |
| [nullsec-linux](https://github.com/bad-antics/nullsec-linux) | Security Linux distro (140+ tools) |

## ⚠️ Legal

For **authorized automotive security testing only**. Never fuzz ECUs in vehicles in traffic.

## 📜 License

MIT License — [@bad-antics](https://github.com/bad-antics)

---

<div align="center">

*Part of the [NullSec Automotive Security Suite](https://github.com/bad-antics)*

</div>
