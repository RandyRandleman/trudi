# Linux-native Windows artifact parsing

TRUDI parses Windows Event Logs, Prefetch and SRUM **natively on Linux** — no
Windows host or VM, no Windows containers, no Wine, no Windows DLLs, no
`RtlDecompressBufferEx`, no ESENT, and no remote Windows worker.

The abstraction is the **artifact**, not the tool: `artifact.parse_windows_*`
tools produce canonical, versioned records; parser-specific output is preserved
but is never the public contract.

---

## Why the EZ Tools path could not stay

| Tool | What actually happens on Linux | Consequence |
|------|-------------------------------|-------------|
| **PECmd** | Win8+ Prefetch is `MAM`/Xpress-Huffman compressed. PECmd decompresses it through the Windows API `RtlDecompressBufferEx`, which does not exist on Linux. | **Broken.** Modern `.pf` files could not be parsed at all — the single most common execution artifact on every Windows host acquired since 2012. |
| **SrumECmd** | Reads `SRUDB.dat` through ESE/ManagedEsent, a Windows database engine. | **Unusable**, and it was never wired into TRUDI: SRUM had *no* parser. The gates referenced SRUM and pointed at `ez.sqlecmd`, a **SQLite** parser that cannot open an ESE database. |
| **EvtxECmd** | Managed .NET with no Windows API dependency — it *does* run on Linux. | Not broken, but architecturally wrong for TRUDI: CSV-only output, map-rendered text presented as the primary data, structured `EventData` flattened away, and a .NET runtime in the evidence path. |

Two of the three were correctness problems; the third was a data-model problem.
All three are now served by Linux-native parsers.

---

## Backends

| Artifact | Tool | Backend | Pinned version | License |
|---|---|---|---|---|
| `.evtx` | `artifact.parse_windows_event_logs` | [`evtx_dump`](https://github.com/omerbenamram/evtx) (Rust) | `0.12.2` | MIT OR Apache-2.0 |
| `.pf` | `artifact.parse_windows_prefetch` | `trudi-prefetch` (this repo, `rust/trudi-prefetch`) over [`prefetch-core`](https://crates.io/crates/prefetch-core) | helper `0.1.0`, core `0.1.1` | MIT helper over Apache-2.0 core |
| `SRUDB.dat` | `artifact.parse_windows_srum` | [`chainsaw analyse srum`](https://github.com/WithSecureLabs/chainsaw) | tag `v2.10.2` | **GPL-3.0** (separate binary — see below) |

`artifact.parser_capabilities` reports, for each backend: name, version vs the
pinned version, artifact types, supported format versions, recovery support,
offline provider-template support, license, limitations, and any health error.

Install/verify:

```bash
scripts/install_linux_parsers.sh              # pinned, checksum-verified
python -c "import json,core.parsers as p; print(json.dumps(p.capabilities(), indent=2))"
```

A missing backend **fails the parse immediately** with `parser_unavailable`, the
artifact type, the expected binary, the env override and an install hint. No
other parser is silently substituted; every result names the parser that ran.

---

## Canonical schema — `trudi.artifact.v1`

One JSON object per line, written under `analysis/`, `exports/` or `reports/`:

```json
{
  "schema_version": "trudi.artifact.v1",
  "artifact_type": "windows.evtx",
  "source": {
    "path": "evidence/Security.evtx",
    "absolute_path": "/root/cases/DC01-001/evidence/Security.evtx",
    "case_root": "/root/cases/DC01-001",
    "sha256": "…64 hex…",
    "size": 1048576,
    "record_number": 1234
  },
  "parser":     { "name": "evtx_dump", "version": "0.12.2", "adapter_version": "1.0.0" },
  "timestamps": { "event_time_utc": "2020-09-19T03:40:49.123456Z" },
  "data":       { "…normalized TRUDI fields…": null },
  "raw":        { "…the parser's own record, untouched…": null },
  "warnings":   [ { "code": "missing_timestamp", "message": "…" } ],
  "parse_status": "complete",
  "recovered": false
}
```

Rules that hold for every record:

* `source.path` is **case-relative** when a case root can be found (absolute
  path kept separately), so records move between hosts without rewriting.
* every primary input is **SHA-256'd before parsing**; SRUM also records the
  SOFTWARE hive digest.
* `parser.version` is the **pinned** version actually executed.
* `data` (normalized) and `raw` (parser-native) are separate. Unrecognized
  columns are preserved, not dropped — SRUM keeps them in
  `data.additional_fields`.
* `warnings` are structured; nothing is silently discarded.
* `parse_status` is `complete` / `partial` / `failed`, and `recovered` says
  whether records came from chunks that failed checksum validation.

`artifact.export_ez_csv` renders these records into EZ-style CSV for analysts and
legacy tooling. It is a **presentation layer**; column parity with EvtxECmd/PECmd
is approximate and is not claimed to be field-for-field.

---

## EVTX specifics

```
artifact.parse_windows_event_logs(
    evtx_path, output_path,
    event_ids="4624,4688", channels="Security", providers="…",
    recover=True, include_raw=True, max_records=0, wevt_cache=None)
```

* Streams JSONL from `evtx_dump -o jsonl` and normalizes record-by-record —
  a multi-GB log never lands in memory.
* Preserves record ID, timestamp, provider (name + GUID), channel, computer,
  event ID, level (+ name), task/opcode/keywords, user SID, process/thread IDs,
  and structured `EventData` / `UserData`.
* **Deterministic ordering**: the parser runs single-threaded (`-t 1`), so record
  order is stable across runs.
* **Recovery**: `recover=True` (default) parses chunks with bad checksums (dirty
  logs) and marks the resulting records `recovered: true`. `recover=False` passes
  `--validate-checksums` for a strict read.
* Corrupt records, decode failures and parser stderr become structured warnings;
  the run continues and is reported as `partial`.
* **Offline provider templates**: `artifact.build_wevt_cache` extracts
  `WEVT_TEMPLATE` resources from PE files on the *acquired* filesystem
  (`/mnt/<host>/Windows/System32`, recursive) into a portable `.wevtcache`, which
  `parse_windows_event_logs(wevt_cache=…)` then uses for rendering. No Windows
  system is involved.
* Rendered message text is **never** treated as more authoritative than the
  record's structured fields.
* Raw BinXML for a bounded record range: `artifact.event_record_xml`.

**EvtxECmd maps** are not used. If you want map-style enrichment, implement it as
a post-processing stage over canonical records. Eric Zimmerman's maps are MIT
licensed in their repository; verify the license text at the revision you copy
before vendoring any of them here.

---

## Prefetch specifics

```
artifact.parse_windows_prefetch(prefetch_path, output_path)
```

* `trudi-prefetch` (Rust, `#![forbid(unsafe_code)]`, no `unwrap`) emits one JSONL
  record per file; `prefetch-core` carries its own clean-room MS-XCA
  Xpress-Huffman decoder, so `MAM`-compressed files parse on Linux.
* Extracted: format version, executable name, run count, **all stored last-run
  times** (up to 8), volume device path / serial / creation time, referenced
  filenames and their count, container type and whether the file was compressed,
  plus the prefetch hash **taken from the file name** (labelled as such).
* Directory input is processed in sorted order; symlinks are skipped; oversized
  files are rejected before being read.
* Per-file errors are structured (`unsupported_version`, `bad_signature`,
  `too_short`, `decompress_failed`, `truncated_record`, `too_large`) and never
  abort the corpus.

### Known gaps (not worked around, reported)

| Gap | Behaviour |
|---|---|
| SCCA **v17/23/26** (XP / Vista / 7 / 8.1) | Structured `unsupported_version` error per file, naming the version. No partial guess. |
| File-metrics, trace-chain, MFT entry/sequence references, directory strings | Not decoded. Every record lists them in `data.unsupported_sections` so absence is never mistaken for "not present in the file". |
| Prefetch hash | Filename-derived, not read from the file body. |

If you need v17/23/26 or the undecoded sections, evaluate `libscca`/`pyscca`
(self-described alpha), Dissect (AGPL-3.0 — incompatible with TRUDI's MIT
distribution if linked) or Artemis, and add them as an explicit, separately
reported backend — never as a silent fallback.

---

## SRUM specifics

```
artifact.parse_windows_srum(srudb_path, software_hive, output_path,
                            sru_directory=None, stats_only=False)
```

* `SRUDB.dat` is required; the **matching SOFTWARE hive is required** and its
  absence returns a structured `incomplete_input` error naming what is missing.
  TRUDI does not fall back to a generic ESE export and call it SRUM.
* Both inputs are copied into a **private per-job working directory**; the
  originals are never opened for writing, repaired, or log-replayed. The test
  suite asserts byte-and-mtime equality of the evidence after a run.
* `sru_directory` additionally copies companion transaction logs (`SRU*.log`,
  `SRUDB.jfm`, `.chk`) next to the working copy so chainsaw sees a complete set.
* Output preserves the source table name/GUID and the raw row, and normalizes
  application, user SID, interface, byte counts, energy and timestamp fields.
  Unrecognized columns are kept in `data.additional_fields`.
* Dirty / corrupt / unsupported database conditions are reported as
  `ese_database_condition` warnings or a failed result — never silently ignored.

### Licensing note (read before redistributing)

chainsaw is **GPL-3.0**; TRUDI is MIT. TRUDI does not copy, link, or vendor
chainsaw source: it executes an unmodified, separately installed release binary
and exchanges data through files and process arguments. `install_linux_parsers.sh`
also places chainsaw's own LICENSE next to the installed binary.

Distributing a **container image** that bundles the chainsaw binary is a
distribution of that binary and carries GPL-3.0 obligations (notably making the
corresponding source available to recipients). That is a licensing question for
whoever ships the image, not a conclusion this document makes for you. Options:

* install chainsaw at deploy time rather than baking it into a published image;
* bake it in and satisfy GPL-3.0 (ship the license, offer the source, keep the
  binary unmodified and separately replaceable) — which is the intent of
  `--skip-chainsaw` and the `TRUDI_CHAINSAW` override;
* run without it: SRUM then reports `parser_unavailable` and nothing else breaks.

If chainsaw cannot be used at all, [Artemis](https://github.com/puffyCid/artemis)
(MIT) is the fallback candidate. Its current CLI must be re-checked before use —
older `--alt-file` / `--alt-path` flags should not be assumed — and it would be
registered as its own backend in `core/parsers.py`, reported by name in every
result, with an explicit fallback warning.

---

## Migration for existing callers

| Old call | New call | Behaviour |
|---|---|---|
| `ez.evtxecmd(evtx_path, output_dir, output_file)` | `artifact.parse_windows_event_logs(evtx_path, output_path)` | The old name still works as a **deprecated alias**: it runs the native backend, writes canonical JSONL (`<output_file>.jsonl`) **and** the EZ-style CSV at the original path. `maps_dir` is ignored and reported. |
| `ez.pecmd(prefetch_path, output_dir, output_file)` | `artifact.parse_windows_prefetch(prefetch_path, output_path)` | Same pattern: native backend, JSONL + CSV. |
| *(nothing — SRUM was unreachable)* | `artifact.parse_windows_srum(srudb, software_hive, output_path)` | New capability. |

Aliases exist for compatibility, not for new work: they cannot express filters,
recovery mode, WEVT caches, or the canonical record's warnings and provenance.
Read canonical records with `read.read_output` so every citation stays traced.

Deprecated configuration: `EvtxECmd/Maps` and `PECmd.dll` are no longer consulted.
`.NET` and the remaining EZ Tools (MFTECmd, RECmd, Amcache, AppCompatCache,
LECmd, JLECmd, SBECmd, SQLECmd, RBCmd, WxTCmd, bstrings, rla) are still required
by other TRUDI tools, so the runtime stays — but EvtxECmd and PECmd can be
dropped from the image.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `parser_unavailable` | Backend not installed. Run `scripts/install_linux_parsers.sh`, or point `TRUDI_EVTX_DUMP` / `TRUDI_PREFETCH_BIN` / `TRUDI_CHAINSAW` at it. |
| `version_matches_pin: false` | A different parser version is on PATH. Fine for ad-hoc work; re-pin before comparing results across cases. |
| Prefetch `unsupported_version` | SCCA v17/23/26 file (pre-Win10). Use `$MFT`, UserAssist, Amcache or ShimCache for that host's execution evidence. |
| Prefetch `decompress_failed` | Truncated or damaged `MAM` stream — the file is corrupt, not the parser. |
| SRUM `incomplete_input` | Extract `Windows/System32/config/SOFTWARE` from the same image and pass `software_hive=`. |
| SRUM `ese_database_condition` | Dirty or partially-written database. Collect the `sru/` transaction logs and pass `sru_directory=`; TRUDI will not repair the evidence. |
| EVTX run reports `partial` | Expected on dirty logs. Check `warnings` — chunk checksum failures with `recover=True` mean records were carved from damaged chunks and are marked `recovered`. |
| Provider text missing | Build a `.wevtcache` from the acquired System32 with `artifact.build_wevt_cache` and pass `wevt_cache=`. Structured fields remain authoritative either way. |

---

## Test corpus

Fixtures are **synthetic and generated from format documentation**
(`tests/fixtures/artifact_fixtures.py`) — redistributable, with no acquired
evidence. They cover: SCCA v30 (single/multiple volumes, 8 run times), v17/23/26
and unknown versions, truncated files, bad signatures, malformed UTF-16 names,
invalid offsets, `MAM` containers with truncated streams; EVTX records with named
EventData, UserData, missing timestamps, missing payloads, multiple channels and
providers, malformed JSONL, empty logs; SRUM array-shaped and table-keyed output,
unknown shapes, dirty-database stderr, and missing-hive input.

Not covered by shipped fixtures, and honestly labelled as such:

* a **real MAM-compressed `.pf`** (no encoder exists to synthesize one; set
  `TRUDI_TEST_PREFETCH_SAMPLE` to an operator-supplied file to exercise it);
* a **real `SRUDB.dat`** — SRUM normalization is validated against synthetic
  chainsaw output only;
* **differential comparison against EZ Tools or libscca**. No claim of
  byte-for-byte or field-for-field equivalence with EvtxECmd/PECmd is made
  anywhere in this implementation, and none should be made without such a test.
