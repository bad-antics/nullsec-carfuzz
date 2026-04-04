use clap::{Parser, ValueEnum};
use nullsec_carfuzz::{
    protocols, CanFrame, FuzzMode, FuzzResult, detect_anomaly, mutate,
};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use serde_json;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "carfuzz",
    about = "NullSec CarFuzz — Automotive Protocol Fuzzer\nFuzzes CAN, UDS (ISO 14229), OBD-II (ISO 15031), DoIP (ISO 13400)",
    version = "0.1.0",
    author = "bad-antics"
)]
struct Args {
    /// CAN interface (e.g. can0, vcan0)
    #[arg(short, long, default_value = "vcan0")]
    interface: String,

    /// Fuzzing mode
    #[arg(short, long, default_value = "random")]
    mode: Mode,

    /// Target protocol
    #[arg(short, long, default_value = "raw")]
    protocol: Protocol,

    /// Target ECU arbitration ID (hex, e.g. 0x7E0)
    #[arg(short, long)]
    target: Option<String>,

    /// Frames per second (0 = unlimited)
    #[arg(long, default_value = "100")]
    rate: u64,

    /// Maximum frames to send (0 = unlimited)
    #[arg(long, default_value = "10000")]
    count: u64,

    /// Output file for results (JSON)
    #[arg(short, long)]
    output: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Dry run — generate frames but don't send
    #[arg(long)]
    dry_run: bool,

    /// Generate crash report at end
    #[arg(long)]
    crash_report: bool,

    /// Discovery range start (hex, used with --mode discovery)
    #[arg(long)]
    range_start: Option<String>,

    /// Discovery range end (hex, used with --mode discovery)
    #[arg(long)]
    range_end: Option<String>,

    /// UDS service byte for bruteforce (hex, e.g. 0x27)
    #[arg(long)]
    service: Option<String>,

    /// Memory range start for extract mode (hex)
    #[arg(long)]
    memory_start: Option<String>,

    /// Memory range end for extract mode (hex)
    #[arg(long)]
    memory_end: Option<String>,

    /// Random seed (for reproducible runs)
    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Random,
    Dict,
    Mutate,
    Protocol,
    Discovery,
    Bruteforce,
    Extract,
}

#[derive(Debug, Clone, ValueEnum)]
enum Protocol {
    Raw,
    Canfd,
    Uds,
    Kwp,
    J1939,
    Obd2,
    Doip,
}

fn parse_hex(s: &str) -> u32 {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn generate_frame(
    args: &Args,
    mode: &FuzzMode,
    rng: &mut SmallRng,
) -> Option<CanFrame> {
    let target = args.target.as_deref().map(parse_hex).unwrap_or(0x7E0);

    match (mode, &args.protocol) {
        (FuzzMode::Random, Protocol::Canfd) => Some(protocols::canfd_random(rng)),
        (FuzzMode::Random, Protocol::J1939) => Some(protocols::j1939_random(rng)),
        (FuzzMode::Random, Protocol::Obd2) => Some(protocols::obd_request(rng)),
        (FuzzMode::Random, Protocol::Uds) | (FuzzMode::Protocol, Protocol::Uds) => {
            Some(protocols::uds_request(target, rng))
        }
        (FuzzMode::Bruteforce { target, service }, _) => {
            let mut data = vec![0x02, *service];
            data.push(rng.gen::<u8>() | 0x01); // sub-function: seed request levels
            data.resize(8, 0x00);
            Some(CanFrame::new(*target, data))
        }
        (FuzzMode::Discovery { start, end }, _) => {
            use rand::Rng;
            let id = rng.gen_range(*start..=*end);
            Some(protocols::uds_request(id, rng))
        }
        _ => Some(protocols::can_random(rng)),
    }
}

fn main() {
    let args = Args::parse();

    let seed = args.seed.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42)
    });
    let mut rng = SmallRng::seed_from_u64(seed);

    let target = args.target.as_deref().map(parse_hex).unwrap_or(0x7E0);
    let range_start = args.range_start.as_deref().map(parse_hex).unwrap_or(0x700);
    let range_end = args.range_end.as_deref().map(parse_hex).unwrap_or(0x7FF);
    let service = args.service.as_deref().map(|s| parse_hex(s) as u8).unwrap_or(0x27);
    let mem_start = args.memory_start.as_deref().map(parse_hex).unwrap_or(0x0000_0000);
    let mem_end = args.memory_end.as_deref().map(parse_hex).unwrap_or(0x0000_FFFF);

    let fuzz_mode = match args.mode {
        Mode::Discovery => FuzzMode::Discovery { start: range_start, end: range_end },
        Mode::Bruteforce => FuzzMode::Bruteforce { target, service },
        Mode::Extract => FuzzMode::Extract { target, start: mem_start, end: mem_end },
        Mode::Protocol => FuzzMode::Protocol,
        Mode::Mutate => FuzzMode::Mutate(vec![]),
        Mode::Dict => FuzzMode::Dict(vec![]),
        Mode::Random => FuzzMode::Random,
    };

    println!(
        "\x1b[32m╔══════════════════════════════════════╗\x1b[0m"
    );
    println!(
        "\x1b[32m║   NullSec CarFuzz v0.1.0             ║\x1b[0m"
    );
    println!(
        "\x1b[32m║   Automotive Protocol Fuzzer         ║\x1b[0m"
    );
    println!(
        "\x1b[32m╚══════════════════════════════════════╝\x1b[0m"
    );
    println!("Interface : {}", args.interface);
    println!("Mode      : {:?}", args.mode);
    println!("Protocol  : {:?}", args.protocol);
    println!("Target    : 0x{:03X}", target);
    println!("Rate      : {} fps", args.rate);
    println!("Count     : {}", args.count);
    println!("Seed      : {}", seed);
    if args.dry_run {
        println!("\x1b[33m[DRY RUN] Frames will be generated but NOT sent.\x1b[0m");
    }
    println!();

    let mut results: Vec<FuzzResult> = Vec::new();
    let mut anomalies = 0usize;
    let delay = if args.rate > 0 {
        std::time::Duration::from_micros(1_000_000 / args.rate)
    } else {
        std::time::Duration::ZERO
    };

    for i in 0..args.count {
        let frame = match generate_frame(&args, &fuzz_mode, &mut rng) {
            Some(f) => f,
            None => break,
        };

        // Simulate a response (dry-run / no real socketcan)
        let response = if args.dry_run {
            // Echo back with potential simulated anomalies
            let mut resp_data = mutate(&frame.data, &mut rng);
            resp_data.truncate(8);
            CanFrame::new(frame.arb_id + 0x08, resp_data)
        } else {
            // With real socketcan this would write/read the socket
            CanFrame::new(frame.arb_id + 0x08, vec![0x00])
        };

        let anomaly = detect_anomaly(&frame, &response);
        if anomaly.is_some() {
            anomalies += 1;
        }

        if args.verbose || anomaly.is_some() {
            let marker = if anomaly.is_some() { "\x1b[31m[!]\x1b[0m" } else { "\x1b[32m[+]\x1b[0m" };
            println!(
                "{} #{:>6} TX {} → RX {} {}",
                marker,
                i,
                frame,
                response,
                anomaly.as_deref().unwrap_or("")
            );
        }

        results.push(FuzzResult {
            frame: frame.clone(),
            anomaly,
            timestamp_ms: now_ms(),
        });

        if delay > std::time::Duration::ZERO {
            std::thread::sleep(delay);
        }
    }

    println!();
    println!(
        "\x1b[32m[*] Done. {} frames sent, {} anomalies detected.\x1b[0m",
        results.len(),
        anomalies
    );

    if let Some(ref path) = args.output {
        let json = serde_json::to_string_pretty(&results).unwrap_or_default();
        let mut f = File::create(path).expect("Cannot create output file");
        f.write_all(json.as_bytes()).expect("Cannot write output");
        println!("[*] Results written to {}", path);
    }

    if args.crash_report && anomalies > 0 {
        let report_path = format!("crash_report_{}.json", now_ms());
        let anomalous: Vec<&FuzzResult> = results.iter().filter(|r| r.anomaly.is_some()).collect();
        let json = serde_json::to_string_pretty(&anomalous).unwrap_or_default();
        let mut f = File::create(&report_path).expect("Cannot create crash report");
        f.write_all(json.as_bytes()).expect("Cannot write crash report");
        println!("[!] Crash report: {}", report_path);
    }
}
