# NullSec CarFuzz Usage Guide

## Quick Start

```bash
# Install
./install.sh

# Basic CAN bus fuzzing
carfuzz --interface can0 --mode random

# Targeted UDS fuzzing
carfuzz --interface can0 --protocol uds --target 0x7E0
```

## Fuzzing Modes

### Random Fuzzing
```bash
carfuzz --interface can0 --mode random --rate 1000
```
Generates random CAN frames at specified rate (frames/sec).

### Dictionary Fuzzing
```bash
carfuzz --interface can0 --mode dict --dict automotive.dict
```
Uses predefined message patterns from dictionary file.

### Mutation Fuzzing
```bash
carfuzz --interface can0 --mode mutate --seed captured.log
```
Mutates captured legitimate traffic.

### Protocol-Aware Fuzzing
```bash
carfuzz --interface can0 --mode protocol --protocol uds
```
Generates protocol-compliant but edge-case messages.

## Supported Protocols

| Protocol | Flag | Description |
|----------|------|-------------|
| Raw CAN | `--protocol raw` | Raw CAN 2.0A/B frames |
| CAN-FD | `--protocol canfd` | CAN Flexible Data-rate |
| UDS | `--protocol uds` | ISO 14229 diagnostics |
| KWP2000 | `--protocol kwp` | ISO 14230 diagnostics |
| J1939 | `--protocol j1939` | SAE heavy-duty |
| OBD-II | `--protocol obd2` | On-board diagnostics |

## Output Options

```bash
# Save results to file
carfuzz --interface can0 --output results.json

# Real-time monitoring
carfuzz --interface can0 --verbose

# Generate crash report
carfuzz --interface can0 --crash-report
```

## Safety Features

- `--rate-limit`: Prevent bus flooding
- `--filter`: Target specific arbitration IDs
- `--timeout`: Automatic session termination
- `--dry-run`: Validate without sending

## Examples

### ECU Discovery
```bash
carfuzz --interface can0 --mode discovery --range 0x700-0x7FF
```

### Security Access Bruteforce
```bash
carfuzz --interface can0 --mode bruteforce --target 0x7E0 --service 0x27
```

### Firmware Extraction Fuzzing
```bash
carfuzz --interface can0 --mode extract --target 0x7E0 --memory 0x00000-0xFFFFF
```
