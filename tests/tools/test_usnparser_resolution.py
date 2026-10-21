"""USN journal parsing: binary discovery, real parse, and honest failure modes.

Regression for "Tool not found: /usr/local/bin/usnparser" — the wrapper used to
hard-code a path that the `usnparser` pip package never creates (its CLI is
installed as `usn.py`), so a missing binary looked like absent USN evidence.
"""
import os
import shutil
import struct

import pytest

from tools.misc import _resolve_usnparser, usnparser_parse

import sys

#: Resolve the CLI next to the running interpreter (venv/bin/usn.py) so these
#: tests do not depend on PATH ordering inside a pytest-xdist worker.
USN_BIN = (os.environ.get("TRUDI_USNPARSER")
           or shutil.which("usn.py")
           or os.path.join(os.path.dirname(sys.executable), "usn.py"))
HAVE_USN = bool(USN_BIN and os.path.isfile(USN_BIN) and os.access(USN_BIN, os.X_OK))
FT_2020_09_19 = 132449604494103203


def usn_record(usn: int, frn: int, parent: int, name: str, reason: int, filetime: int) -> bytes:
    """A USN_RECORD_V2 (MajorVersion 2), 8-byte aligned — per MS-FSCC."""
    nb = name.encode("utf-16-le")
    length = 60 + len(nb)
    pad = (-length) % 8
    return struct.pack("<IHHQQQQIIIIHH", length + pad, 2, 0, frn, parent, usn,
                       filetime, reason, 0, 0, 32, len(nb), 60) + nb + b"\x00" * pad


@pytest.fixture
def journal(tmp_path):
    """Synthetic $J: leading zero run (as on a real sparse journal) + 3 records."""
    data = b"\x00" * 4096
    data += usn_record(0x1000, 0x2000000000001, 0x5000000000005, "coreupdater.exe", 0x100, FT_2020_09_19)
    data += usn_record(0x1100, 0x2000000000002, 0x5000000000005, "secret.zip", 0x1000, FT_2020_09_19 + 10**7)
    data += usn_record(0x1200, 0x2000000000003, 0x5000000000005, "Szechuan Sauce.txt", 0x200, FT_2020_09_19 + 2 * 10**7)
    p = tmp_path / "usnjrnl_J.bin"
    p.write_bytes(data)
    return str(p)


class TestResolution:
    def test_env_override_is_honoured(self, tmp_path, monkeypatch):
        fake = tmp_path / "myusn"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        monkeypatch.setenv("TRUDI_USNPARSER", str(fake))
        assert _resolve_usnparser() == str(fake)

    def test_non_executable_override_is_ignored(self, tmp_path, monkeypatch):
        f = tmp_path / "notexec"
        f.write_text("x")
        monkeypatch.setenv("TRUDI_USNPARSER", str(f))
        assert _resolve_usnparser() != str(f)

    def test_missing_parser_reports_fallback_not_absence_of_evidence(self, tmp_path, monkeypatch):
        journal = tmp_path / "j.bin"
        journal.write_bytes(usn_record(1, 2, 3, "x.exe", 0x100, FT_2020_09_19))
        monkeypatch.setenv("TRUDI_USNPARSER", "/nonexistent/usn")
        monkeypatch.setattr("tools.misc._resolve_usnparser", lambda: None)
        r = usnparser_parse(str(journal), str(tmp_path / "out.csv"))
        assert r["success"] is False and r["tool_unavailable"] is True
        assert "MFTECmd" in r["fallback"]
        assert "NOT absence of USN evidence" in r["fallback"]
        assert "pip install usnparser" in r["install_hint"]

    def test_rejects_bad_output_format(self, tmp_path):
        journal = tmp_path / "j.bin"
        journal.write_bytes(usn_record(1, 2, 3, "x.exe", 0x100, FT_2020_09_19))
        r = usnparser_parse(str(journal), str(tmp_path / "o.csv"), output_format="xml")
        assert r["success"] is False and "output_format" in r["error"]

    def test_output_path_into_evidence_is_refused(self, tmp_path):
        ev = tmp_path / "evidence"
        ev.mkdir()
        with pytest.raises(ValueError):
            usnparser_parse(str(tmp_path / "j.bin"), str(ev / "out.csv"))


@pytest.mark.skipif(not HAVE_USN, reason="usnparser (usn.py) not installed")
class TestRealParse:
    @pytest.fixture(autouse=True)
    def pin_binary(self, monkeypatch):
        """Pin BOTH the parser path and the real executor.

        tools.misc.run is mocked by an autouse fixture in test_misc.py whose
        patch can still be active when this module runs in the same xdist
        worker; without this, these tests silently exercise a MagicMock.
        """
        from core.executor import run as real_run
        monkeypatch.setenv("TRUDI_USNPARSER", USN_BIN)
        monkeypatch.setattr("tools.misc.run", real_run)

    def test_parses_records_from_synthetic_journal(self, journal, tmp_path):
        out = str(tmp_path / "usn.csv")
        r = usnparser_parse(journal, out)
        assert r["success"] and r["records_parsed"] == 3
        text = open(out).read()
        assert "coreupdater.exe" in text and "secret.zip" in text
        assert "FILE_CREATE" in text and "FILE_DELETE" in text
        assert "2020-09-19" in text                      # incident-period timestamps
        assert r["field_limitation"].startswith("csv/body output omits")

    def test_bodyfile_format(self, journal, tmp_path):
        out = str(tmp_path / "usn.body")
        r = usnparser_parse(journal, out, output_format="body")
        assert r["success"] and r["records_parsed"] == 3
        assert "(USN: FILE_CREATE)" in open(out).read()

    def test_all_zero_journal_short_circuits_without_hanging(self, tmp_path):
        """usnparser 4.1.5 loops forever on an all-zero journal; the wrapper must
        detect that before invoking it and explain the likely extraction error."""
        empty = tmp_path / "empty_J.bin"
        empty.write_bytes(b"\x00" * 8192)
        r = usnparser_parse(str(empty), str(tmp_path / "empty.csv"))
        assert r["success"] is False and r["records_parsed"] == 0
        assert "zeros" in r["error"] and "$J data attribute" in r["error"]
