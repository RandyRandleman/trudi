"""Cortex XDR offline collector: detect it and normalize it into a KAPE-style evidence folder.

Standalone:
    python3 -I xdr_collector.py COLLECTOR OUTDIR    # COLLECTOR = the .zip or its unzipped folder
    python3 -I xdr_collector.py --detect COLLECTOR  # exit 0 if it is an XDR offline collector

OUTDIR/
  C/...         raw files rebuilt at their original Windows paths from the collector's manifests
                (SHA-256 checked against Cortex's own record; $USNJrnl:$J is written
                as $Extend/$J, as KAPE does)
  xdr-parsed/   Cortex's pre-parsed results (<artifact>.json) and live-response snapshots
                (process_listing, port_listing, handles, dns_cache, ...): third-party parser output
  collector/    manifest.json, cortex-xdr-payload.log, provenance.tsv, NORMALIZED.json (summary)
Nothing in the collection is executed; member paths are sanitized (no absolute paths, no '..').
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

FORMAT = "cortex_xdr_offline_collector"


class _Source:
    """Uniform read access to a collector given as a zip or as its unzipped folder."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.zip = zipfile.ZipFile(self.path) if self.path.is_file() else None
        if self.zip is None:
            root = (
                self.path / "output"
                if (self.path / "output" / "manifest.json").is_file()
                else self.path
            )
            self.root = root

    def names(self) -> list[str]:
        if self.zip is not None:
            return self.zip.namelist()
        return [
            "output/" + str(p.relative_to(self.root)).replace(os.sep, "/")
            for p in self.root.rglob("*")
            if p.is_file()
        ]

    def read(self, name: str) -> bytes:
        if self.zip is not None:
            return self.zip.read(name)
        return (self.root / name.split("/", 1)[1]).read_bytes()


def detect(path: str | Path) -> dict[str, Any] | None:
    """Return the collector's identity if *path* is an XDR offline collector, else None."""
    try:
        src = _Source(path)
        names = src.names()
    except (OSError, zipfile.BadZipFile, ValueError):
        return None
    if "output/manifest.json" not in names or not any(
        n.endswith("/script_output.zip") for n in names
    ):
        return None
    try:
        m = json.loads(src.read("output/manifest.json"))
    except (ValueError, KeyError, OSError):
        return None
    if (
        not isinstance(m, dict)
        or "files" not in m
        or not ({"agentStatus", "configuration_name"} & set(m))
    ):
        return None
    agent = m.get("agentStatus") or {}
    return {
        "format": FORMAT,
        "configuration": m.get("configuration_name"),
        "device_name": agent.get("deviceName"),
        "device_domain": agent.get("deviceDomain"),
        "user": f"{agent.get('userDomain', '')}\\{agent.get('userName', '')}".strip("\\"),
        "os_version": agent.get("osVersion"),
        "artifacts": len(m.get("files", [])),
    }


def safe_rel(win_path: str) -> str:
    p = win_path.replace("/", "\\")
    m = re.match(r"^([A-Za-z]):\\(.*)$", p)
    drive, rest = (m.group(1).upper(), m.group(2)) if m else ("UNKNOWN", p.lstrip("\\"))
    parts = []
    for seg in rest.split("\\"):
        if seg in ("", ".", ".."):
            continue
        if seg.lower() == "$usnjrnl:$j":
            seg = "$J"
        parts.append(seg.replace(":", "_"))
    return os.path.join(drive, *parts)


def _file_manifest(data: bytes) -> list[dict[str, Any]] | None:
    try:
        j = json.loads(data)
    except ValueError:
        return None
    if (
        isinstance(j, dict)
        and isinstance(j.get("entries"), list)
        and j["entries"]
        and isinstance(j["entries"][0], dict)
        and "files" in j["entries"][0]
    ):
        return [f for e in j["entries"] for f in e.get("files", [])]
    return None


def normalize(collector: str | Path, out: str | Path) -> dict[str, Any]:
    """Normalize *collector* into *out*; return a summary (also collector/NORMALIZED.json)."""
    ident = detect(collector)
    if ident is None:
        raise ValueError(f"not a Cortex XDR offline collector: {collector}")
    src = _Source(collector)
    out = Path(out)
    (out / "xdr-parsed").mkdir(parents=True, exist_ok=True)
    (out / "collector").mkdir(parents=True, exist_ok=True)
    for name in ("output/manifest.json", "output/cortex-xdr-payload.log"):
        if name in src.names():
            (out / "collector" / Path(name).name).write_bytes(src.read(name))
    prov: list[tuple[Any, ...]] = []
    written: dict[str, str] = {}
    dup = bad = parsed = 0
    for member in sorted(n for n in src.names() if n.endswith("/script_output.zip")):
        artifact = member.split("/")[1]
        inner = zipfile.ZipFile(io.BytesIO(src.read(member)))
        names = set(inner.namelist())
        files: list[dict[str, Any]] = []
        for mf in ("manifest.json", "script_output.txt"):
            if mf in names:
                files = _file_manifest(inner.read(mf)) or []
                if files:
                    break
        for f in files:
            arc = str(f.get("archivedPath", "")).replace("\\", "/")
            if arc not in names:
                continue
            rel = safe_rel(str(f["path"]))
            data = inner.read(arc)
            sha = hashlib.sha256(data).hexdigest()
            ok = sha == f.get("sha256", sha)
            bad += not ok
            if rel in written:
                dup += 1
                prov.append(
                    (
                        f["path"],
                        f"{artifact}/{arc}",
                        len(data),
                        sha,
                        artifact,
                        "duplicate" + ("" if written[rel] == sha else "-DIFFERENT"),
                    )
                )
                continue
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            written[rel] = sha
            prov.append(
                (
                    f["path"],
                    f"{artifact}/{arc}",
                    len(data),
                    sha,
                    artifact,
                    "ok" if ok else "SHA-MISMATCH",
                )
            )
        if "script_output.txt" in names:
            raw = inner.read("script_output.txt")
            if _file_manifest(raw) is not None:
                continue
            try:
                json.loads(raw)
                ext = "json"
            except ValueError:
                ext = "txt"
            stem = artifact.replace("-parsing", "").replace("-collection", "")
            (out / "xdr-parsed" / f"{stem}.{ext}").write_bytes(raw)
            parsed += 1
    with open(out / "collector" / "provenance.tsv", "w") as fh:
        fh.write("original_path\tarchived_path\tsize\tsha256\tartifact\tstatus\n")
        for r in prov:
            fh.write("\t".join(map(str, r)) + "\n")
    summary = dict(
        ident,
        raw_files=len(written),
        duplicates=dup,
        sha_mismatches=bad,
        parsed_outputs=parsed,
        source=str(collector),
        layout={
            "raw": "C/ (original paths)",
            "parsed": "xdr-parsed/",
            "provenance": "collector/provenance.tsv",
        },
    )
    (out / "collector" / "NORMALIZED.json").write_text(json.dumps(summary, indent=2))
    return summary


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--detect":
        ident = detect(argv[1])
        print(json.dumps(ident, indent=2) if ident else "not a Cortex XDR offline collector")
        return 0 if ident else 1
    if len(argv) != 2:
        print(__doc__)
        return 2
    s = normalize(argv[0], argv[1])
    print(
        f"{s['device_name']} ({s['configuration']}): raw files written: {s['raw_files']}  "
        f"duplicates skipped: {s['duplicates']}  sha mismatches: {s['sha_mismatches']}  "
        f"pre-parsed outputs: {s['parsed_outputs']}"
    )
    return 1 if s["sha_mismatches"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
