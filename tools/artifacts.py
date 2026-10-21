"""Artifact-oriented, Linux-native Windows artifact parsers.

Public MCP surface (namespace `artifact`):

    artifact.parse_windows_event_logs   .evtx      → evtx_dump (Rust, MIT/Apache-2.0)
    artifact.parse_windows_prefetch     .pf        → trudi-prefetch (prefetch-core, Apache-2.0)
    artifact.parse_windows_srum         SRUDB.dat  → chainsaw analyse srum (GPL-3.0, separate binary)
    artifact.event_record_xml           raw BinXML for specific records
    artifact.build_wevt_cache           offline provider templates from acquired PE files
    artifact.parser_capabilities        what is installed, its version, and its limits
    artifact.export_ez_csv              EZ-compatible CSV as a PRESENTATION layer

None of these use .NET, Wine, Windows DLLs, RtlDecompressBufferEx, ESENT, or a
remote Windows worker. Every tool writes canonical `trudi.artifact.v1` JSONL
(see core/artifact_schema.py) under analysis/, exports/, or reports/, and returns
a summary — never the whole corpus — to the agent.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from typing import Any, Iterator, Optional

from fastmcp import FastMCP

from core import output_safe, DEFAULT_TIMEOUT, VOL_TIMEOUT
from core.paths import assert_output_safe, is_evidence_path
from core import artifact_schema as sch
from core import parsers as pr

mcp = FastMCP("artifacts")

ADAPTER_VERSION = "1.0.0"

# Bounded by default: an agent-facing result never carries a whole log.
MAX_WARNINGS_RETURNED = 25
MAX_SAMPLE_RECORDS = 3
_STDERR_CAP = 200_000


# ── shared plumbing ──────────────────────────────────────────────────────────

def _err(message: str, **fields: Any) -> dict:
    out = {"success": False, "error": message}
    out.update(fields)
    return out


def _work_dir(output_path: str) -> str:
    """Private, per-job working directory beside the output (never in evidence)."""
    base = os.path.dirname(os.path.abspath(output_path)) or "."
    assert_output_safe(base)
    d = os.path.join(base, ".trudi-work", uuid.uuid4().hex)
    os.makedirs(d, exist_ok=True)
    return d


def _cleanup(path: str) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def _safe_input(path: str, what: str) -> tuple[str | None, dict | None]:
    """Resolve an evidence input path safely: it must exist and must not be a
    symlink chain escaping to somewhere else unexpected. Returns (real, error)."""
    if not path:
        return None, _err(f"{what} is required")
    expanded = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(expanded):
        return None, _err(f"{what} not found: {path}")
    real = os.path.realpath(expanded)
    if os.path.islink(expanded) and os.path.dirname(real) != os.path.dirname(expanded):
        return None, _err(
            f"{what} is a symlink pointing outside its directory ({expanded} -> {real}); "
            "refusing to follow it out of the evidence tree"
        )
    return real, None


def _collect(input_path: str, suffix: str, max_files: int = 20_000) -> list[str]:
    """Deterministically ordered list of matching files (file or directory input)."""
    if os.path.isfile(input_path):
        return [input_path]
    found: list[str] = []
    for entry in sorted(os.listdir(input_path)):
        p = os.path.join(input_path, entry)
        if os.path.islink(p):
            continue
        if os.path.isfile(p) and entry.lower().endswith(suffix):
            found.append(p)
        if len(found) >= max_files:
            break
    return found


def _open_output(output_path: str) -> Any:
    assert_output_safe(output_path)
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    return open(output_path, "w", encoding="utf-8")


def _parser_block(name: str, version: str) -> dict:
    return {"name": name, "version": version, "adapter_version": ADAPTER_VERSION}


def _annotate_coverage(window: dict | None, session_ids: list[int] | None = None) -> None:
    """Best-effort: stamp coverage_window on the current tool_call trace entry so
    the negative_completeness / attribution gates see the same signal they get
    from the legacy EZ path. Never raises."""
    try:
        from core.execution_log import log
        cid = getattr(log, "last_call_id", None)
        if callable(cid):
            cid = cid()
        if not cid:
            return
        fields: dict[str, Any] = {}
        if window and window.get("start") and window.get("end"):
            fields["coverage_window"] = window
        if session_ids:
            fields["session_artifact"] = True
            fields["session_event_ids"] = sorted(session_ids)
        if fields:
            log.annotate_tool_call(cid, **fields)
    except Exception:
        pass


def _run_streaming(cmd: list[str], *, timeout: int, stdout_path: str,
                   max_bytes: int | None = None) -> dict:
    """Run a parser with stdout redirected to a file and stderr captured.

    Argument array only — no shell string is ever constructed from caller input.
    """
    import time as _time
    start = _time.perf_counter()
    result: dict[str, Any] = {
        "cmd": cmd, "exit_code": None, "timed_out": False,
        "stderr": "", "elapsed_seconds": 0.0, "output_truncated": False,
    }
    try:
        with open(stdout_path, "wb") as out:
            proc = subprocess.run(
                cmd, stdout=out, stderr=subprocess.PIPE, timeout=timeout, check=False,
            )
        result["exit_code"] = proc.returncode
        result["stderr"] = (proc.stderr or b"").decode("utf-8", "replace")[:_STDERR_CAP]
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        result["stderr"] = f"parser timed out after {timeout}s"
    except OSError as e:
        result["stderr"] = f"parser failed to execute: {e}"
    if max_bytes is not None and os.path.exists(stdout_path):
        if os.path.getsize(stdout_path) > max_bytes:
            result["output_truncated"] = True
    result["elapsed_seconds"] = round(_time.perf_counter() - start, 2)
    return result


def _iter_jsonl(path: str) -> Iterator[tuple[int, Any, str | None]]:
    """Stream a JSONL file: (line_no, parsed_or_None, error). Bounded memory."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield i, json.loads(line), None
            except json.JSONDecodeError as e:
                yield i, None, str(e)


# ── EVTX ─────────────────────────────────────────────────────────────────────

_LEVELS = {0: "Undefined", 1: "Critical", 2: "Error", 3: "Warning",
           4: "Information", 5: "Verbose"}


def _attr(node: Any, key: str) -> Any:
    """evtx_dump JSON keeps XML attributes under '#attributes'."""
    if isinstance(node, dict):
        attrs = node.get("#attributes")
        if isinstance(attrs, dict) and key in attrs:
            return attrs[key]
        if key in node:
            return node[key]
    return None


def _scalar(node: Any) -> Any:
    if isinstance(node, dict):
        for k in ("#text", "#attributes"):
            if k in node and not isinstance(node[k], dict):
                return node[k]
        return node.get("#text", node)
    return node


def _normalize_evtx(event: dict) -> tuple[dict, str | None, list[dict]]:
    """(normalized data, event_time_utc, warnings) from one evtx_dump record."""
    warns: list[dict] = []
    ev = event.get("Event") if isinstance(event.get("Event"), dict) else event
    system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
    provider = system.get("Provider", {})
    execution = system.get("Execution", {})

    event_id = _scalar(system.get("EventID"))
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        warns.append(sch.warning("event_id_unparsed", f"EventID not an integer: {event_id!r}"))
        event_id = None

    level_raw = _scalar(system.get("Level"))
    try:
        level = int(level_raw)
    except (TypeError, ValueError):
        level = None
    time_created = _attr(system.get("TimeCreated"), "SystemTime")

    data = {
        "event_record_id": _scalar(system.get("EventRecordID")),
        "event_id": event_id,
        "provider_name": _attr(provider, "Name"),
        "provider_guid": _attr(provider, "Guid"),
        "channel": _scalar(system.get("Channel")),
        "computer": _scalar(system.get("Computer")),
        "level": level,
        "level_name": _LEVELS.get(level) if level is not None else None,
        "task": _scalar(system.get("Task")),
        "opcode": _scalar(system.get("Opcode")),
        "keywords": _scalar(system.get("Keywords")),
        "user_sid": _attr(system.get("Security"), "UserID"),
        "process_id": _attr(execution, "ProcessID"),
        "thread_id": _attr(execution, "ThreadID"),
        "event_data": ev.get("EventData"),
        "user_data": ev.get("UserData"),
        "has_event_data": ev.get("EventData") is not None,
        "has_user_data": ev.get("UserData") is not None,
    }
    if data["event_data"] is None and data["user_data"] is None:
        warns.append(sch.warning(
            "no_payload", "record carries neither EventData nor UserData"))
    if not time_created:
        warns.append(sch.warning("missing_timestamp", "System/TimeCreated/SystemTime absent"))
    return data, time_created, warns


@mcp.tool()
@output_safe
def parse_windows_event_logs(
    evtx_path: str,
    output_path: str,
    event_ids: Optional[str] = None,
    channels: Optional[str] = None,
    providers: Optional[str] = None,
    recover: bool = True,
    include_raw: bool = True,
    max_records: int = 0,
    wevt_cache: Optional[str] = None,
    timeout: int = VOL_TIMEOUT,
) -> dict:
    """
    Parse Windows Event Logs (.evtx) to canonical trudi.artifact.v1 JSONL — Linux-native.

    Backed by the Rust `evtx_dump` parser (no .NET, no Windows APIs). Structured
    EventData/UserData is preserved; rendered message text is never treated as
    more authoritative than the record's own fields.

    evtx_path: a single .evtx file or a directory of them (processed in sorted order).
    output_path: .jsonl under analysis/, exports/, or reports/.
    event_ids / channels / providers: comma-separated post-parse filters.
    recover: True keeps records from chunks with bad checksums (dirty logs) and
             marks each affected file's records recovered=True.
    include_raw: keep the parser's own record under `raw` (doubles output size).
    max_records: stop after N canonical records (0 = no limit); sets parse_status=partial.
    wevt_cache: optional .wevtcache built by artifact.build_wevt_cache for offline
                provider-template rendering.
    """
    src, err = _safe_input(evtx_path, "evtx_path")
    if err:
        return err
    try:
        binary, version = pr.require("evtx_dump", sch.ARTIFACT_EVTX)
    except pr.ParserUnavailable as e:
        return e.payload

    files = _collect(src, ".evtx")
    if not files:
        return _err(f"no .evtx files found at {evtx_path}")

    want_ids = {int(x) for x in event_ids.replace(" ", "").split(",") if x.strip().isdigit()} \
        if event_ids else None
    want_channels = {c.strip().lower() for c in channels.split(",") if c.strip()} \
        if channels else None
    want_providers = {p.strip().lower() for p in providers.split(",") if p.strip()} \
        if providers else None

    work = _work_dir(output_path)
    parser_block = _parser_block("evtx_dump", version)
    totals = {"files": 0, "records_parsed": 0, "records_written": 0, "records_skipped": 0}
    all_warnings: list[dict] = []
    samples: list[dict] = []
    window: dict[str, Any] = {}
    session_ids: set[int] = set()
    failed_files: list[dict] = []
    truncated = False

    try:
        from tools._gates._session import SESSION_EVENT_IDS
    except Exception:                                    # pragma: no cover
        SESSION_EVENT_IDS = set()                        # type: ignore[assignment]

    try:
        with _open_output(output_path) as out:
            for path in files:
                if truncated:
                    break
                totals["files"] += 1
                digest = sch.sha256_file(path)
                raw_out = os.path.join(work, f"{os.path.basename(path)}.jsonl")
                cmd = [binary, "-o", "jsonl", "-f", raw_out, "--no-confirm-overwrite",
                       "-t", "1"]                        # 1 thread ⇒ deterministic order
                if not recover:
                    cmd.append("--validate-checksums")
                if wevt_cache:
                    cache, cache_err = _safe_input(wevt_cache, "wevt_cache")
                    if cache_err:
                        return cache_err
                    cmd += ["--wevt-cache", cache]
                cmd.append(path)

                run = _run_streaming(cmd, timeout=timeout, stdout_path=os.path.join(work, "stdout.bin"))
                file_warnings: list[dict] = []
                if run["stderr"]:
                    for line in run["stderr"].splitlines():
                        line = line.strip()
                        if line:
                            file_warnings.append(sch.warning("parser_stderr", line, file=os.path.basename(path)))
                if run["timed_out"] or (run["exit_code"] not in (0, None) and not os.path.exists(raw_out)):
                    failed_files.append({"file": path, "exit_code": run["exit_code"],
                                         "stderr": run["stderr"][:2000]})
                    all_warnings.extend(file_warnings)
                    continue

                file_status = sch.PARSE_COMPLETE if run["exit_code"] == 0 and not file_warnings \
                    else sch.PARSE_PARTIAL
                for _lineno, obj, jerr in _iter_jsonl(raw_out):
                    if jerr:
                        file_warnings.append(sch.warning(
                            "jsonl_decode_error", jerr, file=os.path.basename(path)))
                        continue
                    totals["records_parsed"] += 1
                    data, event_time, warns = _normalize_evtx(obj)
                    if want_ids is not None and data["event_id"] not in want_ids:
                        totals["records_skipped"] += 1
                        continue
                    if want_channels is not None and str(data["channel"] or "").lower() not in want_channels:
                        totals["records_skipped"] += 1
                        continue
                    if want_providers is not None and str(data["provider_name"] or "").lower() not in want_providers:
                        totals["records_skipped"] += 1
                        continue

                    rec = sch.make_record(
                        artifact_type=sch.ARTIFACT_EVTX,
                        source=sch.source_block(path, sha256=digest,
                                                record_number=data.get("event_record_id")),
                        parser=parser_block,
                        timestamps={"event_time_utc": event_time},
                        data=data,
                        raw=obj if include_raw else None,
                        warnings=warns,
                        parse_status=file_status,
                        recovered=bool(recover and file_status == sch.PARSE_PARTIAL),
                    )
                    out.write(json.dumps(rec, default=str) + "\n")
                    totals["records_written"] += 1
                    if event_time:
                        if not window.get("start") or event_time < window["start"]:
                            window["start"] = event_time
                        if not window.get("end") or event_time > window["end"]:
                            window["end"] = event_time
                    if data["event_id"] in SESSION_EVENT_IDS:
                        session_ids.add(data["event_id"])
                    if len(samples) < MAX_SAMPLE_RECORDS:
                        samples.append({k: data[k] for k in
                                        ("event_record_id", "event_id", "provider_name",
                                         "channel", "computer")} | {"event_time_utc": event_time})
                    if max_records and totals["records_written"] >= max_records:
                        truncated = True
                        break
                all_warnings.extend(file_warnings)
                if not include_raw:
                    all_warnings.append(sch.warning(
                        "raw_omitted", "include_raw=False: parser-native records were not stored",
                        file=os.path.basename(path)))
                try:
                    os.remove(raw_out)
                except OSError:
                    pass
    finally:
        _cleanup(work)

    status = sch.PARSE_COMPLETE
    if truncated or failed_files or all_warnings:
        status = sch.PARSE_PARTIAL
    if totals["records_written"] == 0 and failed_files:
        status = sch.PARSE_FAILED

    _annotate_coverage(window or None, sorted(session_ids))
    return {
        "success": status != sch.PARSE_FAILED,
        "artifact_type": sch.ARTIFACT_EVTX,
        "schema_version": sch.SCHEMA_VERSION,
        "parser": parser_block,
        "output_path": output_path,
        "parse_status": status,
        "truncated_by_max_records": truncated,
        "recovery_mode": recover,
        "wevt_cache": wevt_cache,
        "coverage_window": window or None,
        "session_event_ids": sorted(session_ids),
        "totals": totals,
        "failed_files": failed_files,
        "warning_count": len(all_warnings),
        "warnings": all_warnings[:MAX_WARNINGS_RETURNED],
        "sample_records": samples,
        "read_next": "Use read.read_output on output_path to query these records.",
    }


@mcp.tool()
@output_safe
def event_record_xml(
    evtx_file: str,
    output_path: str,
    record_range: str = "0-9",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Dump RAW BinXML for a bounded range of records from one .evtx file.

    record_range: evtx_dump `--events` range, offsets relative to the file
    (e.g. "0-99" or "5,10-20"). Kept separate from the JSONL parse so the common
    path never pays for XML rendering.
    """
    src, err = _safe_input(evtx_file, "evtx_file")
    if err:
        return err
    if not os.path.isfile(src):
        return _err("event_record_xml takes a single .evtx file")
    try:
        binary, version = pr.require("evtx_dump", sch.ARTIFACT_EVTX)
    except pr.ParserUnavailable as e:
        return e.payload
    assert_output_safe(output_path)
    cmd = [binary, "-o", "xml", "-f", output_path, "--no-confirm-overwrite",
           "-t", "1", "--events", record_range, src]
    run = _run_streaming(cmd, timeout=timeout, stdout_path=os.path.join(_work_dir(output_path), "stdout.bin"))
    return {
        "success": run["exit_code"] == 0,
        "artifact_type": sch.ARTIFACT_EVTX,
        "parser": _parser_block("evtx_dump", version),
        "output_path": output_path,
        "record_range": record_range,
        "source_sha256": sch.sha256_file(src),
        "stderr": run["stderr"][:4000],
        "elapsed_seconds": run["elapsed_seconds"],
    }


@mcp.tool()
@output_safe
def build_wevt_cache(
    pe_path: str,
    output_path: str,
    recursive: bool = True,
    extensions: str = "exe,dll,sys",
    timeout: int = VOL_TIMEOUT,
) -> dict:
    """
    Build a portable offline provider-template cache (.wevtcache) from PE files
    taken from the ACQUIRED Windows filesystem (e.g. /mnt/<host>/Windows/System32).

    No Windows system is involved: WEVT_TEMPLATE resources are read straight out
    of the PE files. Feed the result to parse_windows_event_logs(wevt_cache=...)
    so records whose embedded templates are missing can still be rendered.
    """
    src, err = _safe_input(pe_path, "pe_path")
    if err:
        return err
    try:
        binary, version = pr.require("evtx_dump", sch.ARTIFACT_EVTX)
    except pr.ParserUnavailable as e:
        return e.payload
    assert_output_safe(output_path)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    cmd = [binary, "extract-wevt-templates", "-i", src, "-o", output_path,
           "--extensions", extensions, "--overwrite"]
    if recursive:
        cmd.append("-r")
    work = _work_dir(output_path)
    try:
        run = _run_streaming(cmd, timeout=timeout, stdout_path=os.path.join(work, "stdout.txt"))
    finally:
        _cleanup(work)
    ok = run["exit_code"] == 0 and os.path.exists(output_path)
    return {
        "success": ok,
        "parser": _parser_block("evtx_dump", version),
        "wevt_cache": output_path if ok else None,
        "source": src,
        "stderr": run["stderr"][:4000],
        "elapsed_seconds": run["elapsed_seconds"],
        "note": "Offline template rendering only — provider message text remains "
                "secondary to the record's structured fields.",
    }


# ── Prefetch ─────────────────────────────────────────────────────────────────

def _normalize_prefetch(rec: dict, path: str, digest: str, parser_block: dict) -> dict:
    """One trudi-prefetch JSONL record → canonical record."""
    warns = [sch.warning("parser_warning", w) for w in rec.get("warnings", []) or []]
    status = sch.PARSE_COMPLETE
    data: dict[str, Any] = {
        "executable": None,
        "prefetch_hash_from_filename": rec.get("prefetch_hash_from_filename"),
        "compressed": rec.get("compressed"),
        "container": rec.get("container"),
        "format_version": None,
        "run_count": None,
        "last_run_times_utc": [],
        "volumes": [],
        "referenced_filenames": [],
        "referenced_filename_count": 0,
        "unsupported_sections": rec.get("unsupported_sections", []),
    }
    timestamps: dict[str, Any] = {}

    if rec.get("status") == "error":
        status = sch.PARSE_FAILED
        e = rec.get("error") or {}
        warns.append(sch.warning(e.get("kind", "parse_error"),
                                 e.get("detail", "prefetch parse failed")))
        data["error"] = e
    else:
        d = rec.get("data") or {}
        runs = [sch.filetime_to_utc(t) for t in (d.get("last_run_filetimes") or [])]
        runs = [r for r in runs if r]
        data.update({
            "executable": d.get("executable"),
            "format_version": d.get("format_version"),
            "run_count": d.get("run_count"),
            "last_run_times_utc": runs,
            "referenced_filenames": d.get("filenames", []),
            "referenced_filename_count": d.get("filename_count", 0),
            "volumes": [
                {
                    "device_path": v.get("device_path"),
                    "serial_number_hex": v.get("serial_number_hex"),
                    "serial_number": v.get("serial_number"),
                    "creation_time_utc": sch.filetime_to_utc(v.get("creation_time_filetime")),
                }
                for v in (d.get("volumes") or [])
            ],
        })
        timestamps = {
            "last_run_utc": runs[0] if runs else None,
            "all_run_times_utc": runs,
        }
        if warns:
            status = sch.PARSE_PARTIAL
    return sch.make_record(
        artifact_type=sch.ARTIFACT_PREFETCH,
        source=sch.source_block(path, sha256=digest),
        parser=parser_block,
        timestamps=timestamps,
        data=data,
        raw=rec,
        warnings=warns,
        parse_status=status,
        recovered=False,
    )


@mcp.tool()
@output_safe
def parse_windows_prefetch(
    prefetch_path: str,
    output_path: str,
    timeout: int = VOL_TIMEOUT,
) -> dict:
    """
    Parse Windows Prefetch (.pf) to canonical trudi.artifact.v1 JSONL — Linux-native.

    Uses TRUDI's Rust helper over `prefetch-core`, which carries its own
    clean-room MS-XCA Xpress-Huffman decoder, so MAM-compressed (Win8+) prefetch
    parses without RtlDecompressBufferEx or any Windows API. SCCA v30/31 only —
    older versions return a structured unsupported_version error per file.

    prefetch_path: a single .pf file or a Prefetch directory (sorted order).
    """
    src, err = _safe_input(prefetch_path, "prefetch_path")
    if err:
        return err
    try:
        binary, version = pr.require("trudi_prefetch", sch.ARTIFACT_PREFETCH)
    except pr.ParserUnavailable as e:
        return e.payload

    work = _work_dir(output_path)
    raw_out = os.path.join(work, "prefetch.jsonl")
    parser_block = _parser_block("trudi-prefetch", version)
    totals = {"files": 0, "parsed": 0, "failed": 0}
    by_error: dict[str, int] = {}
    warnings: list[dict] = []
    samples: list[dict] = []
    executed: list[str] = []

    try:
        run = _run_streaming([binary, src], timeout=timeout, stdout_path=raw_out)
        if run["timed_out"]:
            return _err(run["stderr"], artifact_type=sch.ARTIFACT_PREFETCH, parser=parser_block)
        if run["exit_code"] not in (0, 3):
            return _err(
                f"trudi-prefetch exited {run['exit_code']}: {run['stderr'][:1000]}",
                artifact_type=sch.ARTIFACT_PREFETCH, parser=parser_block,
            )
        with _open_output(output_path) as out:
            for _ln, obj, jerr in _iter_jsonl(raw_out):
                if jerr:
                    warnings.append(sch.warning("jsonl_decode_error", jerr))
                    continue
                totals["files"] += 1
                path = obj.get("path") or src
                digest = sch.sha256_file(path) if os.path.exists(path) else None
                rec = _normalize_prefetch(obj, path, digest, parser_block)
                out.write(json.dumps(rec, default=str) + "\n")
                if rec["parse_status"] == sch.PARSE_FAILED:
                    totals["failed"] += 1
                    kind = (obj.get("error") or {}).get("kind", "unknown")
                    by_error[kind] = by_error.get(kind, 0) + 1
                else:
                    totals["parsed"] += 1
                    d = rec["data"]
                    if d.get("executable"):
                        executed.append(d["executable"])
                    if len(samples) < MAX_SAMPLE_RECORDS:
                        samples.append({
                            "executable": d.get("executable"),
                            "run_count": d.get("run_count"),
                            "last_run_utc": (d.get("last_run_times_utc") or [None])[0],
                            "format_version": d.get("format_version"),
                        })
                warnings.extend(rec["warnings"])
    finally:
        _cleanup(work)

    status = sch.PARSE_COMPLETE if not totals["failed"] else (
        sch.PARSE_PARTIAL if totals["parsed"] else sch.PARSE_FAILED)
    return {
        "success": status != sch.PARSE_FAILED,
        "artifact_type": sch.ARTIFACT_PREFETCH,
        "schema_version": sch.SCHEMA_VERSION,
        "parser": parser_block,
        "output_path": output_path,
        "parse_status": status,
        "totals": totals,
        "failures_by_kind": by_error,
        "executables": sorted(set(executed))[:100],
        "warning_count": len(warnings),
        "warnings": warnings[:MAX_WARNINGS_RETURNED],
        "sample_records": samples,
        "limitations": list(pr.BACKENDS["trudi_prefetch"].limitations),
        "read_next": "Use read.read_output on output_path to query these records.",
    }


# ── SRUM ─────────────────────────────────────────────────────────────────────

_SRUM_FIELD_ALIASES = {
    "application": ("AppId", "Application", "app", "ExeInfo", "AppID"),
    "user_sid": ("UserId", "SidId", "User", "UserSid", "Sid"),
    "interface": ("InterfaceLuid", "Interface", "L2ProfileId"),
    "bytes_sent": ("BytesSent", "bytes_sent", "SentBytes"),
    "bytes_received": ("BytesRecvd", "BytesReceived", "bytes_received", "RecvBytes"),
    "timestamp": ("TimeStamp", "Timestamp", "timestamp", "EventTimestamp"),
    "table": ("table", "Table", "TableName", "source_table"),
    "energy": ("EnergyUsage", "DesignedCapacity", "FullChargedCapacity", "ChargeLevel"),
}


def _pick(row: dict, keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def _normalize_srum_row(row: dict, table: str | None) -> dict:
    """Normalize one chainsaw SRUM row; unrecognized columns are preserved."""
    known: set[str] = set()
    data: dict[str, Any] = {"source_table": table or _pick(row, _SRUM_FIELD_ALIASES["table"])}
    for field_name, aliases in _SRUM_FIELD_ALIASES.items():
        if field_name == "table":
            continue
        val = _pick(row, aliases)
        data[field_name] = val
        known.update(k for k in aliases if k in row)
    data["additional_fields"] = {k: v for k, v in row.items()
                                 if k not in known and k not in ("table", "Table")}
    return data


@mcp.tool()
@output_safe
def parse_windows_srum(
    srudb_path: str,
    software_hive: str,
    output_path: str,
    sru_directory: Optional[str] = None,
    stats_only: bool = False,
    timeout: int = VOL_TIMEOUT,
) -> dict:
    """
    Parse SRUM (SRUDB.dat — application/network/energy resource usage) to
    canonical trudi.artifact.v1 JSONL — Linux-native.

    Backed by `chainsaw analyse srum`, a separately installed GPL-3.0 binary
    (never linked into TRUDI). No ESENT, no Windows.

    srudb_path:     C:\\Windows\\System32\\sru\\SRUDB.dat from the acquired image.
    software_hive:  the MATCHING SOFTWARE hive — required to resolve provider
                    GUIDs to table meanings. Its absence is a structured
                    incomplete-input error, never a silent generic ESE export.
    sru_directory:  optional sru/ directory; its transaction logs (SRU*.log,
                    SRUDB.jfm) are copied into the private working directory
                    alongside the database. Evidence is never modified.
    """
    src, err = _safe_input(srudb_path, "srudb_path")
    if err:
        return err
    if not software_hive:
        return {
            "success": False,
            "incomplete_input": True,
            "artifact_type": sch.ARTIFACT_SRUM,
            "missing": ["software_hive"],
            "error": "SRUM parsing requires the matching SOFTWARE hive "
                     "(Windows/System32/config/SOFTWARE) to resolve provider GUIDs. "
                     "Extract it from the same image and pass software_hive=.",
        }
    hive, err = _safe_input(software_hive, "software_hive")
    if err:
        return {**err, "incomplete_input": True, "missing": ["software_hive"],
                "artifact_type": sch.ARTIFACT_SRUM}
    try:
        binary, version = pr.require("chainsaw", sch.ARTIFACT_SRUM)
    except pr.ParserUnavailable as e:
        return e.payload

    digest = sch.sha256_file(src)
    hive_digest = sch.sha256_file(hive)
    work = _work_dir(output_path)
    warnings: list[dict] = []
    try:
        # Private working COPY: chainsaw opens the ESE database itself, and a
        # dirty database must never be touched in place.
        db_copy = os.path.join(work, os.path.basename(src))
        shutil.copy2(src, db_copy)
        os.chmod(db_copy, 0o600)
        hive_copy = os.path.join(work, os.path.basename(hive))
        shutil.copy2(hive, hive_copy)
        copied_logs: list[str] = []
        if sru_directory:
            sru, sru_err = _safe_input(sru_directory, "sru_directory")
            if sru_err:
                return sru_err
            if os.path.isdir(sru):
                for entry in sorted(os.listdir(sru)):
                    low = entry.lower()
                    if low.endswith((".log", ".jfm", ".chk")) or low.startswith("sru"):
                        p = os.path.join(sru, entry)
                        if os.path.isfile(p) and not os.path.islink(p) and p != src:
                            shutil.copy2(p, os.path.join(work, entry))
                            copied_logs.append(entry)

        chainsaw_out = os.path.join(work, "srum.json")
        cmd = [binary, "analyse", "srum", "-s", hive_copy, "-o", chainsaw_out, "-q"]
        if stats_only:
            cmd.append("--stats-only")
        cmd.append(db_copy)
        run = _run_streaming(cmd, timeout=timeout, stdout_path=os.path.join(work, "stdout.txt"))
        stderr = run["stderr"]
        low = stderr.lower()
        if run["timed_out"]:
            return _err(stderr, artifact_type=sch.ARTIFACT_SRUM)
        if any(k in low for k in ("dirty", "corrupt", "unsupported", "not a valid")):
            warnings.append(sch.warning("ese_database_condition", stderr[:2000]))
        if run["exit_code"] != 0 or not os.path.exists(chainsaw_out):
            return {
                "success": False,
                "artifact_type": sch.ARTIFACT_SRUM,
                "parser": _parser_block("chainsaw", version),
                "exit_code": run["exit_code"],
                "error": f"chainsaw analyse srum failed: {stderr[:2000] or 'no output produced'}",
                "hint": "If the database is dirty or truncated, that is reported as-is — "
                        "TRUDI does not repair evidence.",
                "warnings": warnings,
            }

        with open(chainsaw_out, "r", encoding="utf-8", errors="replace") as fh:
            try:
                payload = json.load(fh)
            except json.JSONDecodeError as e:
                return _err(f"chainsaw output was not valid JSON: {e}",
                            artifact_type=sch.ARTIFACT_SRUM)

        parser_block = _parser_block("chainsaw", version)
        rows_by_table: list[tuple[str | None, dict]] = []
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    rows_by_table.append((item.get("table") or item.get("Table"), item))
        elif isinstance(payload, dict):
            for table, rows in payload.items():
                if isinstance(rows, list):
                    rows_by_table.extend((table, r) for r in rows if isinstance(r, dict))
                elif isinstance(rows, dict):
                    rows_by_table.append((table, rows))
        if not rows_by_table:
            warnings.append(sch.warning(
                "unrecognized_output_shape",
                "chainsaw produced JSON TRUDI could not split into rows; the raw "
                "output is preserved as a single record"))
            rows_by_table = [(None, {"chainsaw_output": payload})]

        tables: dict[str, int] = {}
        samples: list[dict] = []
        with _open_output(output_path) as out:
            for table, row in rows_by_table:
                data = _normalize_srum_row(row, table)
                ts = data.get("timestamp")
                rec = sch.make_record(
                    artifact_type=sch.ARTIFACT_SRUM,
                    source=sch.source_block(
                        src, sha256=digest,
                        extra={"software_hive": os.path.basename(hive),
                               "software_hive_sha256": hive_digest,
                               "transaction_logs_present": copied_logs}),
                    parser=parser_block,
                    timestamps={"event_time_utc": ts if isinstance(ts, str) else None},
                    data=data,
                    raw=row,
                    warnings=[],
                    parse_status=sch.PARSE_COMPLETE if not warnings else sch.PARSE_PARTIAL,
                )
                out.write(json.dumps(rec, default=str) + "\n")
                key = str(data.get("source_table") or "unknown")
                tables[key] = tables.get(key, 0) + 1
                if len(samples) < MAX_SAMPLE_RECORDS:
                    samples.append({k: data.get(k) for k in
                                    ("source_table", "application", "user_sid",
                                     "bytes_sent", "bytes_received", "timestamp")})
    finally:
        _cleanup(work)

    return {
        "success": True,
        "artifact_type": sch.ARTIFACT_SRUM,
        "schema_version": sch.SCHEMA_VERSION,
        "parser": _parser_block("chainsaw", version),
        "output_path": output_path,
        "parse_status": sch.PARSE_PARTIAL if warnings else sch.PARSE_COMPLETE,
        "records": sum(tables.values()),
        "tables": tables,
        "software_hive_sha256": hive_digest,
        "srudb_sha256": digest,
        "transaction_logs_copied": copied_logs,
        "warning_count": len(warnings),
        "warnings": warnings[:MAX_WARNINGS_RETURNED],
        "sample_records": samples,
        "license_note": "chainsaw is GPL-3.0 and is invoked as a separate, unmodified "
                        "binary; see docs/linux-native-parsers.md.",
        "read_next": "Use read.read_output on output_path to query these records.",
    }


# ── capabilities + presentation layer ────────────────────────────────────────

@mcp.tool()
def parser_capabilities() -> dict:
    """
    Report which Linux-native artifact parsers are installed and operational:
    name, version (vs the pinned version), artifact types, supported format
    versions, recovery support, offline provider-template support, license, and
    known limitations. Call this before an artifact phase — a missing backend
    fails the parse loudly rather than substituting another parser.
    """
    return pr.capabilities()


_EZ_LAYOUTS: dict[str, list[tuple[str, str]]] = {
    # EZ column name → dotted path in the canonical record
    "evtx": [
        ("RecordNumber", "data.event_record_id"),
        ("EventRecordId", "data.event_record_id"),
        ("TimeCreated", "timestamps.event_time_utc"),
        ("EventId", "data.event_id"),
        ("Level", "data.level_name"),
        ("Provider", "data.provider_name"),
        ("Channel", "data.channel"),
        ("Computer", "data.computer"),
        ("UserId", "data.user_sid"),
        ("ProcessId", "data.process_id"),
        ("ThreadId", "data.thread_id"),
        ("PayloadData1", "data.event_data"),
        ("SourceFile", "source.path"),
    ],
    "prefetch": [
        ("SourceFilename", "source.path"),
        ("ExecutableName", "data.executable"),
        ("Hash", "data.prefetch_hash_from_filename"),
        ("Version", "data.format_version"),
        ("RunCount", "data.run_count"),
        ("LastRun", "timestamps.last_run_utc"),
        ("PreviousRun0", "timestamps.all_run_times_utc.1"),
        ("PreviousRun1", "timestamps.all_run_times_utc.2"),
        ("Volume0Name", "data.volumes.0.device_path"),
        ("Volume0Serial", "data.volumes.0.serial_number_hex"),
        ("Volume0Created", "data.volumes.0.creation_time_utc"),
        ("FilesLoadedCount", "data.referenced_filename_count"),
    ],
}


def _dig(rec: Any, dotted: str) -> Any:
    cur = rec
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
    if isinstance(cur, (dict, list)):
        return json.dumps(cur, default=str)
    return cur


@mcp.tool()
@output_safe
def export_ez_csv(
    records_path: str,
    output_path: str,
    layout: str = "evtx",
    max_rows: int = 0,
) -> dict:
    """
    Render canonical trudi.artifact.v1 JSONL into an EZ-Tools-compatible CSV.

    This is a PRESENTATION layer for analysts and legacy tooling — the canonical
    records remain the data model. Column sets approximate EvtxECmd/PECmd output;
    they are NOT claimed to be field-for-field identical.

    layout: "evtx" or "prefetch".
    """
    import csv
    if layout not in _EZ_LAYOUTS:
        return _err(f"unknown layout {layout!r}; expected one of {sorted(_EZ_LAYOUTS)}")
    src, err = _safe_input(records_path, "records_path")
    if err:
        return err
    if is_evidence_path(src):
        return _err("records_path must be produced output under analysis/, exports/ or reports/")
    assert_output_safe(output_path)
    cols = _EZ_LAYOUTS[layout]
    rows = 0
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([c for c, _ in cols])
        for _ln, rec, jerr in _iter_jsonl(src):
            if jerr or not isinstance(rec, dict):
                continue
            w.writerow([_dig(rec, path) for _, path in cols])
            rows += 1
            if max_rows and rows >= max_rows:
                break
    return {
        "success": True,
        "output_path": output_path,
        "layout": layout,
        "rows": rows,
        "note": "EZ-compatible presentation export; canonical records are in "
                f"{os.path.basename(src)}. Column parity with EZ Tools is approximate.",
    }
