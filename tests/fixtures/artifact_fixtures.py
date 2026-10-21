"""Synthetic, fully redistributable fixtures for the Linux-native artifact parsers.

Everything here is generated from format documentation — no third-party sample
files, no acquired evidence, so the corpus carries no licensing or privacy
baggage and can live in the repository.

Prefetch: SCCA payloads are built to the layout `prefetch-core` reads
(header 84 bytes, FileInformation at 84, 96-byte volume records). MAM-compressed
(Xpress-Huffman) samples cannot be generated without an encoder; the compressed
path is covered by a header-detection test plus the upstream crate's own tests,
and by an opt-in integration test against an operator-supplied sample
(TRUDI_TEST_PREFETCH_SAMPLE).
"""
from __future__ import annotations

import struct

FILETIME_2020_09_19 = 132449604494103203      # 2020-09-19T03:40:49Z


def _utf16(text: str, byte_len: int) -> bytes:
    raw = text.encode("utf-16-le") + b"\x00\x00"
    return raw[:byte_len].ljust(byte_len, b"\x00")


def build_scca(
    *,
    version: int = 30,
    executable: str = "COREUPDATER.EXE",
    run_count: int = 3,
    run_times: list[int] | None = None,
    filenames: list[str] | None = None,
    volumes: list[tuple[str, int, int]] | None = None,
    signature: bytes = b"SCCA",
    break_filename_offset: bool = False,
    malformed_utf16: bool = False,
) -> bytes:
    """Build an uncompressed SCCA prefetch payload."""
    run_times = run_times if run_times is not None else [FILETIME_2020_09_19, FILETIME_2020_09_19 - 10**9]
    filenames = filenames if filenames is not None else [
        r"\VOLUME{01d68d85e0da1e22-b0e0e8ff}\WINDOWS\SYSTEM32\COREUPDATER.EXE",
        r"\VOLUME{01d68d85e0da1e22-b0e0e8ff}\WINDOWS\SYSTEM32\NTDLL.DLL",
    ]
    volumes = volumes if volumes is not None else [
        (r"\VOLUME{01d68d85e0da1e22-b0e0e8ff}", 0xB0E0E8FF, FILETIME_2020_09_19 - 10**12),
    ]

    header = bytearray(84)
    struct.pack_into("<I", header, 0, version)
    header[4:8] = signature
    name_bytes = _utf16(executable, 60)
    if malformed_utf16:
        name_bytes = b"\x00\xd8" + name_bytes[2:]          # lone high surrogate
    header[16:76] = name_bytes

    file_info = bytearray(224)                              # v30 FileInformation
    for i, t in enumerate(run_times[:8]):
        struct.pack_into("<q", file_info, 44 + i * 8, t)
    struct.pack_into("<I", file_info, 124, run_count)       # old-layout counter

    body_start = 84 + len(file_info)
    fn_block = b"".join(f.encode("utf-16-le") + b"\x00\x00" for f in filenames)
    fn_off = body_start
    vol_off = fn_off + len(fn_block)

    vol_records = bytearray()
    vol_strings = bytearray()
    strings_base = len(volumes) * 96                         # relative to vol_off
    for dev, serial, ctime in volumes:
        dev_bytes = dev.encode("utf-16-le") + b"\x00\x00"
        rec = bytearray(96)
        struct.pack_into("<I", rec, 0, strings_base + len(vol_strings))
        struct.pack_into("<I", rec, 4, len(dev) + 1)         # chars incl. NUL
        struct.pack_into("<q", rec, 8, ctime)
        struct.pack_into("<I", rec, 16, serial)
        vol_records += rec
        vol_strings += dev_bytes

    struct.pack_into("<I", file_info, 16, 0xFFFFFFF0 if break_filename_offset else fn_off)
    struct.pack_into("<I", file_info, 20, len(fn_block))
    struct.pack_into("<I", file_info, 24, vol_off)
    struct.pack_into("<I", file_info, 28, len(volumes))
    struct.pack_into("<I", file_info, 32, len(vol_records) + len(vol_strings))

    return bytes(header) + bytes(file_info) + fn_block + bytes(vol_records) + bytes(vol_strings)


def build_mam_header_only() -> bytes:
    """A MAM/Xpress-Huffman container whose compressed stream is truncated."""
    return b"MAM\x04" + struct.pack("<I", 24316) + b"\x00" * 16


# ── evtx_dump JSONL records (what the Rust parser emits) ─────────────────────

def evtx_record(
    *,
    record_id: int = 1,
    event_id: int = 4624,
    provider: str = "Microsoft-Windows-Security-Auditing",
    guid: str = "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    channel: str = "Security",
    computer: str = "CITADEL-DC01.citadel.local",
    level: int = 0,
    time: str | None = "2020-09-19T03:40:49.123456Z",
    user_sid: str | None = "S-1-5-18",
    event_data: dict | None = None,
    user_data: dict | None = None,
) -> dict:
    system: dict = {
        "Provider": {"#attributes": {"Name": provider, "Guid": guid}},
        "EventID": event_id,
        "Level": level,
        "Task": 12544,
        "Opcode": 0,
        "Keywords": "0x8020000000000000",
        "EventRecordID": record_id,
        "Channel": channel,
        "Computer": computer,
        "Execution": {"#attributes": {"ProcessID": 964, "ThreadID": 4028}},
    }
    if time:
        system["TimeCreated"] = {"#attributes": {"SystemTime": time}}
    if user_sid:
        system["Security"] = {"#attributes": {"UserID": user_sid}}
    ev: dict = {"System": system}
    if event_data is not None:
        ev["EventData"] = event_data
    if user_data is not None:
        ev["UserData"] = user_data
    return {"Event": ev}


SRUM_CHAINSAW_ARRAY = [
    {"table": "Network Usage", "AppId": r"\Device\HarddiskVolume2\Windows\System32\svchost.exe",
     "UserId": "S-1-5-18", "BytesSent": 10240, "BytesRecvd": 4096,
     "InterfaceLuid": 1689399959552, "TimeStamp": "2020-09-19T03:40:49Z", "OddColumn": "keep-me"},
    {"table": "Application Resource Usage", "AppId": "coreupdater.exe", "UserId": "S-1-5-21-1",
     "TimeStamp": "2020-09-19T03:41:00Z", "ForegroundCycleTime": 99},
]

SRUM_CHAINSAW_BY_TABLE = {
    "Energy Usage": [{"AppId": "chrome.exe", "ChargeLevel": 88, "TimeStamp": "2020-09-19T04:00:00Z"}],
}
