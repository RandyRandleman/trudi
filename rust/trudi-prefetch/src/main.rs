//! trudi-prefetch — Linux-native Windows Prefetch reader for TRUDI.
//!
//! Reads `.pf` files (MAM/Xpress-Huffman compressed, Win8+, or raw SCCA) and
//! writes ONE JSON object per line to stdout. Diagnostics go to stderr. The
//! process never writes files, never opens a network socket, and never executes
//! anything from the evidence it reads.
//!
//! Usage:   trudi-prefetch [--max-files N] [--max-bytes N] <file-or-dir>...
//!          trudi-prefetch --version-json
//!
//! Exit codes:
//!   0  every input parsed
//!   3  at least one input failed to parse (its record carries status="error")
//!   2  usage / no readable input
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const TOOL: &str = "trudi-prefetch";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Pinned in Cargo.toml as `=0.1.1`; surfaced so every record names the parser
/// version that produced it.
const PARSER: &str = "prefetch-core";
const PARSER_VERSION: &str = "0.1.1";
/// Sections present in the SCCA format that this reader does not decode. Named
/// in every record so a consumer never mistakes absence for "not in the file".
const UNSUPPORTED_SECTIONS: [&str; 4] = [
    "file_metrics_array",
    "trace_chain_array",
    "mft_entry_and_sequence_references",
    "directory_strings_array",
];
const DEFAULT_MAX_FILES: usize = 10_000;
/// Refuse absurd inputs before allocating: a real .pf is well under 10 MB.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

fn version_json() -> serde_json::Value {
    serde_json::json!({
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "parser": PARSER,
        "parser_version": PARSER_VERSION,
        "artifact_types": ["windows.prefetch"],
        "supported_format_versions": [30, 31],
        "unsupported_format_versions": [17, 23, 26],
        "supports_compressed_mam": true,
        "supports_recovery": false,
        "unsupported_sections": UNSUPPORTED_SECTIONS,
        "license": "MIT (this helper); Apache-2.0 (prefetch-core)"
    })
}

/// `COREUPDATER.EXE-157C54BB.pf` -> `157C54BB`. Filename-derived, NOT read from
/// the file body — consumers are told which it is.
fn hash_from_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".pf").or_else(|| name.strip_suffix(".PF"))?;
    let (_, tail) = stem.rsplit_once('-')?;
    let ok = !tail.is_empty() && tail.len() <= 16 && tail.chars().all(|c| c.is_ascii_hexdigit());
    ok.then(|| tail.to_ascii_uppercase())
}

fn container_of(bytes: &[u8]) -> (&'static str, bool) {
    match bytes.get(..4) {
        Some([b'M', b'A', b'M', 0x04]) => ("MAM/XpressHuffman", true),
        Some([b'M', b'A', b'M', _]) => ("MAM/unknown-compression", true),
        _ => ("SCCA (uncompressed)", false),
    }
}

fn error_kind(e: &prefetch_core::PrefetchError) -> (&'static str, String) {
    use prefetch_core::PrefetchError as E;
    match e {
        E::TooShort => ("too_short", "file is shorter than a valid prefetch header".into()),
        E::BadSignature => (
            "bad_signature",
            "not a MAM/Xpress-Huffman or raw SCCA prefetch container".into(),
        ),
        E::Decompress(d) => ("decompress_failed", format!("Xpress-Huffman decompression failed: {d:?}")),
        E::UnsupportedVersion(v) => (
            "unsupported_version",
            format!(
                "SCCA format version {v} is not supported by {PARSER} {PARSER_VERSION} \
                 (supported: 30=Win10, 31=Win11)"
            ),
        ),
        E::TruncatedRecord => (
            "truncated_record",
            "an offset/length in the SCCA payload pointed past the end of the file".into(),
        ),
    }
}

fn record_for(path: &Path, max_bytes: u64) -> (serde_json::Value, bool) {
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let mut base = serde_json::json!({
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "parser": PARSER,
        "parser_version": PARSER_VERSION,
        "path": path.to_string_lossy(),
        "file_name": name,
        "prefetch_hash_from_filename": hash_from_filename(&name),
        "warnings": [],
    });

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            base["status"] = "error".into();
            base["error"] = serde_json::json!({"kind": "unreadable", "detail": e.to_string()});
            return (base, false);
        }
    };
    base["size"] = serde_json::json!(meta.len());
    if meta.len() > max_bytes {
        base["status"] = "error".into();
        base["error"] = serde_json::json!({
            "kind": "too_large",
            "detail": format!("{} bytes exceeds the {max_bytes}-byte limit", meta.len())
        });
        return (base, false);
    }

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            base["status"] = "error".into();
            base["error"] = serde_json::json!({"kind": "unreadable", "detail": e.to_string()});
            return (base, false);
        }
    };
    let (container, compressed) = container_of(&bytes);
    base["container"] = container.into();
    base["compressed"] = compressed.into();

    match prefetch_core::parse(&bytes) {
        Ok(info) => {
            let volumes: Vec<serde_json::Value> = info
                .volumes
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "device_path": v.device_path,
                        "serial_number": v.serial,
                        "serial_number_hex": format!("{:08X}", v.serial),
                        "creation_time_filetime": v.creation_time,
                    })
                })
                .collect();
            let mut warnings: Vec<String> = Vec::new();
            if info.executable.is_empty() {
                warnings.push("executable name was empty or undecodable UTF-16".into());
            }
            if info.volumes.is_empty() {
                warnings.push("no volume information block decoded".into());
            }
            base["status"] = "complete".into();
            base["data"] = serde_json::json!({
                "format_version": info.version,
                "executable": info.executable,
                "run_count": info.run_count,
                "last_run_filetimes": info.last_run_times,
                "volumes": volumes,
                "filenames": info.filenames,
                "filename_count": info.filenames.len(),
            });
            base["unsupported_sections"] = serde_json::json!(UNSUPPORTED_SECTIONS);
            base["warnings"] = serde_json::json!(warnings);
            (base, true)
        }
        Err(e) => {
            let (kind, detail) = error_kind(&e);
            base["status"] = "error".into();
            base["error"] = serde_json::json!({"kind": kind, "detail": detail});
            (base, false)
        }
    }
}

/// Collect .pf files from a file or directory argument. Directories are walked
/// one level deep (the Windows Prefetch directory is flat); symlinks are skipped
/// so a crafted link inside evidence cannot pull the reader elsewhere.
fn collect(input: &Path, out: &mut Vec<PathBuf>, max_files: usize) {
    let md = match std::fs::symlink_metadata(input) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{TOOL}: cannot stat {}: {e}", input.display());
            return;
        }
    };
    if md.file_type().is_symlink() {
        eprintln!("{TOOL}: skipping symlink {}", input.display());
        return;
    }
    if md.is_file() {
        out.push(input.to_path_buf());
        return;
    }
    let entries = match std::fs::read_dir(input) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{TOOL}: cannot read directory {}: {e}", input.display());
            return;
        }
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|x| x.eq_ignore_ascii_case("pf"))
                .unwrap_or(false)
        })
        .collect();
    found.sort();                                   // deterministic ordering
    if found.len() > max_files {
        eprintln!(
            "{TOOL}: {} .pf files in {} exceeds --max-files {max_files}; processing the first {max_files}",
            found.len(),
            input.display()
        );
        found.truncate(max_files);
    }
    out.extend(found);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut max_files = DEFAULT_MAX_FILES;
    let mut max_bytes = DEFAULT_MAX_BYTES;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--version-json" => {
                println!("{}", version_json());
                return;
            }
            "--version" => {
                println!("{TOOL} {TOOL_VERSION} ({PARSER} {PARSER_VERSION})");
                return;
            }
            "--max-files" => {
                max_files = args.next().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_MAX_FILES);
            }
            "--max-bytes" => {
                max_bytes = args.next().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_MAX_BYTES);
            }
            "-h" | "--help" => {
                eprintln!("usage: {TOOL} [--max-files N] [--max-bytes N] <file-or-dir>...");
                return;
            }
            other => inputs.push(PathBuf::from(other)),
        }
    }
    if inputs.is_empty() {
        eprintln!("usage: {TOOL} [--max-files N] [--max-bytes N] <file-or-dir>...");
        std::process::exit(2);
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for i in &inputs {
        collect(i, &mut files, max_files);
    }
    if files.is_empty() {
        eprintln!("{TOOL}: no readable .pf input");
        std::process::exit(2);
    }

    // One record per file, flushed as it is produced: bounded memory regardless
    // of corpus size.
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let mut failures = 0usize;
    for f in &files {
        let (rec, ok) = record_for(f, max_bytes);
        if !ok {
            failures += 1;
        }
        if writeln!(w, "{rec}").is_err() {
            std::process::exit(2);                  // downstream closed the pipe
        }
        let _ = w.flush();
    }
    let _ = w.flush();
    eprintln!("{TOOL}: {} file(s), {failures} failed", files.len());
    if failures > 0 {
        std::process::exit(3);
    }
}
