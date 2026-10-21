"""SRUM: incomplete-input handling, normalization, evidence-integrity guarantees.

A stand-in `chainsaw` drives the pipeline deterministically. The real binary is
exercised only for its version probe when installed; no redistributable SRUDB.dat
fixture exists, so end-to-end validation against a real ESE database is an
operator step (see docs/linux-native-parsers.md).
"""
import json
import os
import shutil
import stat
import textwrap

import pytest

from core import parsers as pr
from core.artifact_schema import validate_record
from tests.fixtures import artifact_fixtures as fx

REAL = os.environ.get("TRUDI_CHAINSAW") or shutil.which("chainsaw")


@pytest.fixture
def case(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# case")
    for d in ("evidence", "analysis"):
        (tmp_path / d).mkdir()
    sru = tmp_path / "evidence" / "sru"
    sru.mkdir()
    (sru / "SRUDB.dat").write_bytes(b"\xef\xcd\xab\x89" + b"\x00" * 512)   # ESE magic
    (sru / "SRU00001.log").write_bytes(b"\x00" * 64)
    (sru / "SRUDB.jfm").write_bytes(b"\x00" * 32)
    (tmp_path / "evidence" / "SOFTWARE").write_bytes(b"regf" + b"\x00" * 256)
    return tmp_path


def fake_chainsaw(tmp_path, payload, *, stderr="", exit_code=0, write_output=True):
    script = tmp_path / "fake_chainsaw"
    script.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import sys
        args = sys.argv[1:]
        if "--version" in args:
            print("chainsaw 2.10.1"); sys.exit(0)
        out = args[args.index("-o") + 1] if "-o" in args else None
        if out and {write_output!r}:
            open(out, "w").write({json.dumps(payload)!r})
        sys.stderr.write({stderr!r})
        sys.exit({exit_code})
    """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture
def with_fake(monkeypatch):
    def _install(path):
        monkeypatch.setenv("TRUDI_CHAINSAW", path)
        pr._version_cache.clear()
    yield _install
    pr._version_cache.clear()


def _read(path):
    return [json.loads(l) for l in open(path).read().splitlines() if l.strip()]


class TestIncompleteInput:
    def test_missing_software_hive_is_structured_error(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, fx.SRUM_CHAINSAW_ARRAY))
        from tools.artifacts import parse_windows_srum
        r = parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"), "",
                               str(case / "analysis" / "srum.jsonl"))
        assert r["success"] is False
        assert r["incomplete_input"] is True and r["missing"] == ["software_hive"]
        assert "SOFTWARE" in r["error"]

    def test_nonexistent_hive_is_incomplete_not_generic(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, fx.SRUM_CHAINSAW_ARRAY))
        from tools.artifacts import parse_windows_srum
        r = parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                               str(case / "evidence" / "NOPE"),
                               str(case / "analysis" / "srum.jsonl"))
        assert r["incomplete_input"] is True and r["missing"] == ["software_hive"]

    def test_missing_srudb_is_clean_error(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, fx.SRUM_CHAINSAW_ARRAY))
        from tools.artifacts import parse_windows_srum
        r = parse_windows_srum(str(case / "evidence" / "missing.dat"),
                               str(case / "evidence" / "SOFTWARE"),
                               str(case / "analysis" / "s.jsonl"))
        assert r["success"] is False and "not found" in r["error"]


class TestNormalization:
    def _run(self, case, tmp_path, with_fake, payload, **kw):
        with_fake(fake_chainsaw(tmp_path, payload))
        from tools.artifacts import parse_windows_srum
        out = str(case / "analysis" / "srum.jsonl")
        return parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                                  str(case / "evidence" / "SOFTWARE"), out, **kw), out

    def test_array_output_normalizes_and_keeps_unknown_columns(self, case, tmp_path, with_fake):
        r, out = self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_ARRAY)
        assert r["success"] and r["records"] == 2
        recs = _read(out)
        assert validate_record(recs[0]) == []
        d = recs[0]["data"]
        assert d["source_table"] == "Network Usage"
        assert d["application"].endswith("svchost.exe")
        assert d["user_sid"] == "S-1-5-18"
        assert d["bytes_sent"] == 10240 and d["bytes_received"] == 4096
        assert d["interface"] == 1689399959552
        assert d["additional_fields"]["OddColumn"] == "keep-me"   # nothing discarded
        assert recs[0]["raw"]["BytesSent"] == 10240
        assert recs[0]["timestamps"]["event_time_utc"] == "2020-09-19T03:40:49Z"

    def test_table_keyed_output_shape(self, case, tmp_path, with_fake):
        r, out = self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_BY_TABLE)
        assert r["tables"] == {"Energy Usage": 1}
        assert _read(out)[0]["data"]["energy"] == 88

    def test_unknown_shape_is_preserved_with_warning(self, case, tmp_path, with_fake):
        r, out = self._run(case, tmp_path, with_fake, {"summary": "no rows here"})
        assert any(w["code"] == "unrecognized_output_shape" for w in r["warnings"])
        assert _read(out)[0]["raw"]["chainsaw_output"] == {"summary": "no rows here"}

    def test_hashes_and_provenance_recorded(self, case, tmp_path, with_fake):
        r, out = self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_ARRAY)
        rec = _read(out)[0]
        assert len(r["srudb_sha256"]) == 64 and len(r["software_hive_sha256"]) == 64
        assert rec["source"]["software_hive"] == "SOFTWARE"
        assert rec["parser"]["name"] == "chainsaw"

    def test_transaction_logs_are_copied_not_moved(self, case, tmp_path, with_fake):
        r, _ = self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_ARRAY,
                         sru_directory=str(case / "evidence" / "sru"))
        assert set(r["transaction_logs_copied"]) >= {"SRU00001.log", "SRUDB.jfm"}
        assert (case / "evidence" / "sru" / "SRU00001.log").exists()

    def test_evidence_is_never_modified(self, case, tmp_path, with_fake):
        db = case / "evidence" / "sru" / "SRUDB.dat"
        before = (db.read_bytes(), db.stat().st_mtime_ns)
        self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_ARRAY,
                  sru_directory=str(case / "evidence" / "sru"))
        assert (db.read_bytes(), db.stat().st_mtime_ns) == before

    def test_working_copy_is_cleaned_up(self, case, tmp_path, with_fake):
        self._run(case, tmp_path, with_fake, fx.SRUM_CHAINSAW_ARRAY)
        assert not os.path.exists(str(case / "analysis" / ".trudi-work")) or \
            os.listdir(str(case / "analysis" / ".trudi-work")) == []


class TestErrorPaths:
    def test_dirty_database_condition_is_reported(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, fx.SRUM_CHAINSAW_ARRAY,
                                stderr="warning: database is dirty; logs not replayed\n"))
        from tools.artifacts import parse_windows_srum
        out = str(case / "analysis" / "s.jsonl")
        r = parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                               str(case / "evidence" / "SOFTWARE"), out)
        assert r["parse_status"] == "partial"
        assert any(w["code"] == "ese_database_condition" for w in r["warnings"])

    def test_parser_failure_returns_error_not_partial_data(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, {}, stderr="corrupt ESE page\n",
                                exit_code=1, write_output=False))
        from tools.artifacts import parse_windows_srum
        r = parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                               str(case / "evidence" / "SOFTWARE"),
                               str(case / "analysis" / "s.jsonl"))
        assert r["success"] is False and "chainsaw analyse srum failed" in r["error"]
        assert "does not repair evidence" in r["hint"]

    def test_backend_missing_fails_fast(self, case, monkeypatch):
        monkeypatch.setenv("TRUDI_CHAINSAW", "/nonexistent/chainsaw")
        pr._version_cache.clear()
        from tools.artifacts import parse_windows_srum
        r = parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                               str(case / "evidence" / "SOFTWARE"),
                               str(case / "analysis" / "s.jsonl"))
        pr._version_cache.clear()
        assert r["parser_unavailable"] is True and r["artifact_type"] == "windows.srum"

    def test_output_into_evidence_refused(self, case, tmp_path, with_fake):
        with_fake(fake_chainsaw(tmp_path, fx.SRUM_CHAINSAW_ARRAY))
        from tools.artifacts import parse_windows_srum
        with pytest.raises(ValueError):
            parse_windows_srum(str(case / "evidence" / "sru" / "SRUDB.dat"),
                               str(case / "evidence" / "SOFTWARE"),
                               str(case / "evidence" / "out.jsonl"))


@pytest.mark.skipif(not REAL, reason="chainsaw not installed")
class TestRealChainsaw:
    def test_srum_subcommand_exists(self):
        import subprocess
        out = subprocess.run([REAL, "analyse", "srum", "--help"],
                             capture_output=True, text=True, timeout=30)
        assert "--software" in (out.stdout + out.stderr)

    def test_version_probe(self):
        pr._version_cache.clear()
        version, err = pr.probe_version("chainsaw")
        assert err is None and version.startswith("2.")
