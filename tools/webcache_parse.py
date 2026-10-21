"""Parse an Internet Explorer / legacy Edge WebCacheV01.dat (ESE database).

Standalone on purpose: it needs only the standard library plus libesedb's Python
binding (``pyesedb``, from the ``libesedb-python`` wheel, which plaso also depends on),
so any interpreter that has pyesedb can run it:

    python webcache_parse.py WebCacheV01.dat [--max-rows N] [--json]

What it reports, per container (History, MSHist*, iedownload, Content, Cookies, the
legacy Edge containers, ...): URL, the container's access/modify/create/expiry/sync
times in UTC, cached file name and size, access count, and for downloads the target
path and source URL decoded from the record's header blob.

Limits, stated in the output too:
- ESE databases are usually left "dirty" on a live system. libesedb reads the database
  file only; records still held in the V01*.log transaction logs are not replayed, so a
  dirty database can be missing the most recent activity.
- Compatibility/telemetry containers (iecompat, iecompatua, DNTException, EmieSiteList,
  EmieUserList) are counted but not listed: they hold browser config, not user activity.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import struct
import sys
from typing import Any

SKIP_CONTAINERS = {"iecompat", "iecompatua", "dntexception", "emiesitelist", "emieuserlist"}
TIME_COLUMNS = ("AccessedTime", "ModifiedTime", "CreationTime", "ExpiryTime", "SyncTime")
_EPOCH = _dt.datetime(1601, 1, 1)
_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

# ESE file header: database state is a uint32 at offset 0x34 (2 = dirty shutdown, 3 = clean).
_DB_STATES = {
    1: "just created",
    2: "dirty shutdown",
    3: "clean shutdown",
    4: "being converted",
    5: "force detach",
}


def filetime(value: int | None) -> str:
    if not value or value <= 0:
        return ""
    try:
        return (_EPOCH + _dt.timedelta(microseconds=value // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return ""


def db_state(path: str) -> str:
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x38)
        return _DB_STATES.get(struct.unpack_from("<I", hdr, 0x34)[0], "unknown")
    except (OSError, struct.error):
        return "unknown"


def _value(record: Any, col: int, kind: str) -> Any:
    try:
        if kind == "int":
            return record.get_value_data_as_integer(col)
        if kind == "str":
            return record.get_value_data_as_string(col)
        return record.get_value_data(col)
    except Exception:  # noqa: BLE001 - one unreadable value must not drop the record
        return None


def _u16_strings(blob: bytes | None) -> list[str]:
    if not blob:
        return []
    return [m.group().decode("utf-16-le") for m in _U16.finditer(blob)]


def parse(path: str, max_rows: int = 5000) -> dict[str, Any]:
    import pyesedb  # type: ignore[import-not-found]  # imported here so the module can be imported for its helpers without it

    db = pyesedb.file()
    db.open(path)
    out: dict[str, Any] = {
        "file": path,
        "database_state": db_state(path),
        "containers": [],
        "rows": [],
    }

    names: dict[int, tuple[str, str]] = {}
    cont = db.get_table_by_name("Containers")
    if cont is not None:
        cols = {cont.get_column(i).name: i for i in range(cont.number_of_columns)}
        for rec in cont.records:
            cid = _value(rec, cols.get("ContainerId", -1), "int")
            if cid is None:
                continue
            names[cid] = (
                _value(rec, cols.get("Name", -1), "str") or f"Container_{cid}",
                _value(rec, cols.get("Directory", -1), "str") or "",
            )

    for i in range(db.number_of_tables):
        table = db.get_table(i)
        if not table.name.startswith("Container_"):
            continue
        try:
            cid = int(table.name.split("_", 1)[1])
        except ValueError:
            continue
        name, directory = names.get(cid, (table.name, ""))
        info = {
            "container_id": cid,
            "name": name,
            "directory": directory,
            "records": table.number_of_records,
            "listed": 0,
        }
        out["containers"].append(info)
        if name.lower() in SKIP_CONTAINERS or any(
            name.lower().endswith("_" + s) for s in SKIP_CONTAINERS
        ):
            info["skipped"] = "browser configuration, not user activity"
            continue
        cols = {table.get_column(c).name: c for c in range(table.number_of_columns)}
        for rec in table.records:
            if info["listed"] >= max_rows:
                info["truncated"] = True
                break
            url = _value(rec, cols["Url"], "str") if "Url" in cols else None
            if not url:
                continue
            row = {"container": name, "url": url}
            for tc in TIME_COLUMNS:
                if tc in cols:
                    row[tc] = filetime(_value(rec, cols[tc], "int"))
            for c, key in (
                ("Filename", "filename"),
                ("FileSize", "size"),
                ("AccessCount", "access_count"),
                ("RedirectUrl", "redirect"),
            ):
                if c in cols:
                    v = _value(rec, cols[c], "int" if c in ("FileSize", "AccessCount") else "str")
                    if v not in (None, "", 0):
                        row[key] = v
            if name.lower().startswith("mshist") and row.get("ModifiedTime"):
                # IE quirk: MSHist (daily/weekly history) stores ModifiedTime in the host's
                # LOCAL time, not UTC. Move it out of the UTC column so it cannot skew a timeline.
                row["modified_local_time"] = row.pop("ModifiedTime")
            if name.lower().startswith("iedownload") and "ResponseHeaders" in cols:
                strings = _u16_strings(_value(rec, cols["ResponseHeaders"], "bin"))
                paths = [s for s in strings if re.match(r"^[A-Za-z]:\\", s)]
                urls = [s for s in strings if re.match(r"^(https?|ftp|file)://", s, re.I)]
                if paths:
                    row["download_target"] = paths[0]
                if urls:
                    row["download_url"] = urls[0]
            out["rows"].append(row)
            info["listed"] += 1
    out["rows"].sort(key=lambda r: r.get("AccessedTime") or r.get("ModifiedTime") or "")
    return out


def to_text(result: dict[str, Any]) -> str:
    lines = [
        f"=== IE/Edge WebCache: {result['file']} ===",
        f"database_state: {result['database_state']}"
        + (
            "  (dirty: records still only in the V01*.log transaction logs are NOT included)"
            if result["database_state"] == "dirty shutdown"
            else ""
        ),
        "containers: "
        + ", ".join(
            f"{c['name']}={c['records']}"
            + (" (not listed)" if c.get("skipped") else "")
            + (" (truncated)" if c.get("truncated") else "")
            for c in result["containers"]
        ),
        "note: MSHist* rows keep their modified time as modified_local_time (stored in host local "
        "time by IE); every *_utc column is UTC",
        "accessed_utc\tmodified_utc\tcreated_utc\tcontainer\turl\tdetails",
    ]
    for r in result["rows"]:
        details = []
        for k in (
            "modified_local_time",
            "filename",
            "size",
            "access_count",
            "redirect",
            "download_target",
            "download_url",
            "ExpiryTime",
            "SyncTime",
        ):
            if r.get(k):
                details.append(f"{k}={r[k]}")
        lines.append(
            "\t".join(
                [
                    r.get("AccessedTime", ""),
                    r.get("ModifiedTime", ""),
                    r.get("CreationTime", ""),
                    r["container"],
                    r["url"],
                    "; ".join(details),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    max_rows = 5000
    if "--max-rows" in argv:
        max_rows = int(argv[argv.index("--max-rows") + 1])
    result = parse(argv[0], max_rows=max_rows)
    sys.stdout.write(json.dumps(result) if "--json" in argv else to_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
