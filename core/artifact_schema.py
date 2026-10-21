"""Canonical TRUDI artifact schema (`trudi.artifact.v1`).

Every Linux-native artifact parser (EVTX, Prefetch, SRUM) emits records in this
shape, one JSON object per line. The contract:

* the schema is versioned and the version travels with every record;
* `source.path` is evidence-relative where a case root can be determined, with
  the absolute path kept separately, so records stay portable across hosts;
* every primary input is SHA-256'd before parsing and the digest is in-record;
* the parser name and its PINNED version are recorded — a record can always be
  traced to the exact code that produced it;
* `raw` keeps the parser's own field names untouched; `data` holds the
  normalized TRUDI view. Normalization never destroys unrecognized fields;
* warnings are structured, and completeness/recovery state is explicit.

Presentation layers (e.g. the EZ-compatible CSV export) are built OVER these
records. EZ column names are not the internal model.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
from typing import Any, Iterable

SCHEMA_VERSION = "trudi.artifact.v1"

ARTIFACT_EVTX = "windows.evtx"
ARTIFACT_PREFETCH = "windows.prefetch"
ARTIFACT_SRUM = "windows.srum"

PARSE_COMPLETE = "complete"
PARSE_PARTIAL = "partial"
PARSE_FAILED = "failed"
_PARSE_STATES = (PARSE_COMPLETE, PARSE_PARTIAL, PARSE_FAILED)

# FILETIME epoch (1601-01-01Z) offset in 100-ns ticks.
_FILETIME_EPOCH_DELTA = 116444736000000000
_HASH_CHUNK = 1024 * 1024


def sha256_file(path: str) -> str:
    """SHA-256 of a file, read in bounded chunks (evidence may be multi-GB)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def filetime_to_utc(filetime: int | None) -> str | None:
    """Windows FILETIME (100-ns ticks since 1601) → ISO-8601 UTC, or None.

    Returns None for 0/negative/out-of-range values rather than inventing a
    timestamp; the raw tick value stays in `raw` either way.
    """
    if not filetime or filetime <= 0:
        return None
    try:
        micros = (int(filetime) - _FILETIME_EPOCH_DELTA) // 10
        if micros < 0:
            return None
        return (
            _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
            + _dt.timedelta(microseconds=micros)
        ).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def find_case_root(path: str) -> str | None:
    """Walk up from `path` to the case directory (the one holding CLAUDE.md with
    an analysis/ sibling). Returns None when the file lives outside a case."""
    cur = os.path.dirname(os.path.abspath(path))
    seen = 0
    while cur and cur != os.path.sep and seen < 32:
        if os.path.exists(os.path.join(cur, "CLAUDE.md")) and os.path.isdir(
            os.path.join(cur, "analysis")
        ):
            return cur
        cur = os.path.dirname(cur)
        seen += 1
    return None


def source_block(path: str, *, sha256: str | None = None, record_number: int | None = None,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the `source` block: evidence-relative path first, absolute second."""
    abs_path = os.path.abspath(path)
    root = find_case_root(abs_path)
    rel = os.path.relpath(abs_path, root) if root else os.path.basename(abs_path)
    block: dict[str, Any] = {
        "path": rel,
        "absolute_path": abs_path,
        "case_root": root,
        "sha256": sha256,
        "size": os.path.getsize(abs_path) if os.path.exists(abs_path) else None,
    }
    if record_number is not None:
        block["record_number"] = record_number
    if extra:
        block.update(extra)
    return block


def warning(code: str, message: str, **fields: Any) -> dict[str, Any]:
    """A structured warning. Parsing problems are never silently dropped."""
    w = {"code": code, "message": message}
    w.update(fields)
    return w


def make_record(
    *,
    artifact_type: str,
    source: dict[str, Any],
    parser: dict[str, Any],
    data: dict[str, Any],
    raw: Any = None,
    timestamps: dict[str, Any] | None = None,
    warnings: Iterable[dict[str, Any]] | None = None,
    parse_status: str = PARSE_COMPLETE,
    recovered: bool = False,
) -> dict[str, Any]:
    """Assemble one canonical record."""
    if parse_status not in _PARSE_STATES:
        raise ValueError(f"parse_status must be one of {_PARSE_STATES}")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": artifact_type,
        "source": source,
        "parser": parser,
        "timestamps": timestamps or {},
        "data": data,
        "raw": raw,
        "warnings": list(warnings or []),
        "parse_status": parse_status,
        "recovered": bool(recovered),
    }


_REQUIRED_TOP = (
    "schema_version", "artifact_type", "source", "parser",
    "timestamps", "data", "warnings", "parse_status", "recovered",
)


def validate_record(rec: Any) -> list[str]:
    """Structural validation. Returns a list of problems (empty = valid).

    Deliberately dependency-free: the schema is small, and a hard jsonschema
    dependency in the evidence path is not worth it.
    """
    problems: list[str] = []
    if not isinstance(rec, dict):
        return ["record is not an object"]
    for key in _REQUIRED_TOP:
        if key not in rec:
            problems.append(f"missing required key: {key}")
    if rec.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"schema_version {rec.get('schema_version')!r} != {SCHEMA_VERSION!r}"
        )
    if rec.get("parse_status") not in _PARSE_STATES:
        problems.append(f"invalid parse_status: {rec.get('parse_status')!r}")
    if not isinstance(rec.get("recovered", None), bool):
        problems.append("recovered must be a boolean")
    src = rec.get("source")
    if not isinstance(src, dict):
        problems.append("source must be an object")
    else:
        if not src.get("path"):
            problems.append("source.path is required")
        if os.path.isabs(str(src.get("path", ""))) and src.get("case_root"):
            problems.append("source.path must be evidence-relative when a case root is known")
        sha = src.get("sha256")
        if sha is not None and (not isinstance(sha, str) or len(sha) != 64):
            problems.append("source.sha256 must be a 64-char hex digest or null")
    par = rec.get("parser")
    if not isinstance(par, dict):
        problems.append("parser must be an object")
    else:
        for key in ("name", "version", "adapter_version"):
            if not par.get(key):
                problems.append(f"parser.{key} is required")
    if not isinstance(rec.get("warnings", None), list):
        problems.append("warnings must be a list")
    else:
        for w in rec["warnings"]:
            if not isinstance(w, dict) or "code" not in w or "message" not in w:
                problems.append("each warning needs code and message")
                break
    if not isinstance(rec.get("data", None), dict):
        problems.append("data must be an object")
    return problems
