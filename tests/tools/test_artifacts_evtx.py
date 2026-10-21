"""EVTX: adapter behaviour over parser-shaped JSONL, plus real-binary error paths.

The pipeline tests drive a stand-in `evtx_dump` so filtering, warnings, limits and
schema conformance are deterministic and hermetic. Tests marked `needs_evtx_dump`
exercise the real pinned binary when it is installed.
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

REAL = os.environ.get("TRUDI_EVTX_DUMP") or shutil.which("evtx_dump")
needs_evtx_dump = pytest.mark.skipif(not REAL, reason="evtx_dump not installed")


@pytest.fixture
def case(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# case")
    for d in ("evidence", "analysis"):
        (tmp_path / d).mkdir()
    (tmp_path / "evidence" / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    return tmp_path


def fake_evtx_dump(tmp_path, records, *, stderr="", exit_code=0, name="fake_evtx_dump"):
    """A stand-in for evtx_dump: honours --version and -f <out>, emits fixture JSONL."""
    payload = "\n".join(json.dumps(r) for r in records)
    script = tmp_path / name
    script.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import sys
        args = sys.argv[1:]
        if "--version" in args:
            print("EVTX Parser 0.12.2"); sys.exit(0)
        out = args[args.index("-f") + 1] if "-f" in args else None
        if out:
            open(out, "w").write({payload!r} + ("\\n" if {payload!r} else ""))
        sys.stderr.write({stderr!r})
        sys.exit({exit_code})
    """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture
def with_fake(monkeypatch):
    def _install(path):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", path)
        pr._version_cache.clear()
    yield _install
    pr._version_cache.clear()


def _read(path):
    return [json.loads(l) for l in open(path).read().splitlines() if l.strip()]


class TestEvtxPipeline:
    def test_structured_fields_not_only_message(self, case, tmp_path, with_fake):
        rec = fx.evtx_record(event_data={"TargetUserName": "ricksanchez", "LogonType": "3"})
        with_fake(fake_evtx_dump(tmp_path, [rec]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "evtx.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert r["success"] and r["totals"]["records_written"] == 1
        c = _read(out)[0]
        assert validate_record(c) == []
        d = c["data"]
        assert d["event_record_id"] == 1
        assert d["event_id"] == 4624
        assert d["provider_name"] == "Microsoft-Windows-Security-Auditing"
        assert d["provider_guid"].startswith("{54849625")
        assert d["channel"] == "Security" and d["computer"].startswith("CITADEL-DC01")
        assert d["user_sid"] == "S-1-5-18"
        assert d["process_id"] == 964 and d["thread_id"] == 4028
        assert d["event_data"]["TargetUserName"] == "ricksanchez"
        assert c["timestamps"]["event_time_utc"] == "2020-09-19T03:40:49.123456Z"
        assert c["parser"]["name"] == "evtx_dump" and c["parser"]["version"] == "0.12.2"
        assert c["source"]["sha256"] and c["source"]["path"].startswith("evidence")

    def test_raw_record_preserved_by_default(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "e.jsonl")
        parse_windows_event_logs(str(case / "evidence"), out)
        assert _read(out)[0]["raw"]["Event"]["System"]["EventRecordID"] == 1

    def test_include_raw_false_warns(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "e.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out, include_raw=False)
        assert _read(out)[0]["raw"] is None
        assert any(w["code"] == "raw_omitted" for w in r["warnings"])

    def test_userdata_records_supported(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record(user_data={"RuleName": "x"})]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "u.jsonl")
        parse_windows_event_logs(str(case / "evidence"), out)
        d = _read(out)[0]["data"]
        assert d["has_user_data"] is True and d["user_data"]["RuleName"] == "x"

    def test_record_without_payload_warns(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record(event_data=None)]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "n.jsonl")
        parse_windows_event_logs(str(case / "evidence"), out)
        assert any(w["code"] == "no_payload" for w in _read(out)[0]["warnings"])

    def test_missing_timestamp_warns_not_invents(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record(time=None)]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "t.jsonl")
        parse_windows_event_logs(str(case / "evidence"), out)
        c = _read(out)[0]
        assert c["timestamps"]["event_time_utc"] is None
        assert any(w["code"] == "missing_timestamp" for w in c["warnings"])

    def test_filters_by_event_id_channel_provider(self, case, tmp_path, with_fake):
        recs = [
            fx.evtx_record(record_id=1, event_id=4624),
            fx.evtx_record(record_id=2, event_id=4688),
            fx.evtx_record(record_id=3, event_id=7045, channel="System",
                           provider="Service Control Manager"),
        ]
        with_fake(fake_evtx_dump(tmp_path, recs))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "f.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out, event_ids="4624,7045")
        assert [c["data"]["event_id"] for c in _read(out)] == [4624, 7045]
        assert r["totals"]["records_skipped"] == 1

        r2 = parse_windows_event_logs(str(case / "evidence"), out, channels="system")
        assert [c["data"]["event_id"] for c in _read(out)] == [7045]
        assert r2["totals"]["records_written"] == 1

        parse_windows_event_logs(str(case / "evidence"), out,
                                 providers="Service Control Manager")
        assert [c["data"]["event_record_id"] for c in _read(out)] == [3]

    def test_coverage_window_and_session_ids(self, case, tmp_path, with_fake):
        recs = [fx.evtx_record(record_id=1, time="2020-09-19T03:00:00.000000Z"),
                fx.evtx_record(record_id=2, time="2020-09-19T06:00:00.000000Z")]
        with_fake(fake_evtx_dump(tmp_path, recs))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "c.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert r["coverage_window"] == {"start": "2020-09-19T03:00:00.000000Z",
                                        "end": "2020-09-19T06:00:00.000000Z"}
        assert 4624 in r["session_event_ids"]

    def test_max_records_marks_partial(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record(record_id=i) for i in range(10)]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "m.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out, max_records=3)
        assert r["totals"]["records_written"] == 3
        assert r["truncated_by_max_records"] and r["parse_status"] == "partial"

    def test_parser_stderr_becomes_structured_warning(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()],
                                 stderr="Failed to parse record 42: chunk checksum mismatch\n"))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "w.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert r["parse_status"] == "partial"
        assert any("checksum" in w["message"] for w in r["warnings"])
        assert _read(out)[0]["recovered"] is True           # recover=True default

    def test_recover_false_passes_validate_checksums(self, case, tmp_path, with_fake, monkeypatch):
        seen = {}
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        import tools.artifacts as art
        real = art._run_streaming

        def spy(cmd, **kw):
            seen["cmd"] = cmd
            return real(cmd, **kw)
        monkeypatch.setattr(art, "_run_streaming", spy)
        art.parse_windows_event_logs(str(case / "evidence"),
                                     str(case / "analysis" / "r.jsonl"), recover=False)
        assert "--validate-checksums" in seen["cmd"]

    def test_malformed_jsonl_line_is_reported(self, case, tmp_path, with_fake):
        script = fake_evtx_dump(tmp_path, [fx.evtx_record()])
        # corrupt the emitted payload
        text = open(script).read().replace('open(out, "w").write(',
                                           'open(out, "w").write("{not json}\\n" + ')
        open(script, "w").write(text)
        with_fake(script)
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "j.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert any(w["code"] == "jsonl_decode_error" for w in r["warnings"])
        assert r["totals"]["records_written"] == 1          # the good record still lands

    def test_parser_failure_is_not_silent(self, case, tmp_path, with_fake):
        script = fake_evtx_dump(tmp_path, [], stderr="fatal: bad file\n", exit_code=1)
        open(script, "a").write("")
        with_fake(script)
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "x.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert any("fatal" in w["message"] for w in r["warnings"])

    def test_empty_log_yields_zero_records_and_succeeds(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, []))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "empty.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert r["totals"]["records_written"] == 0 and r["coverage_window"] is None

    def test_directory_is_processed_in_sorted_order(self, case, tmp_path, with_fake):
        (case / "evidence" / "A.evtx").write_bytes(b"ElfFile\x00")
        (case / "evidence" / "Z.evtx").write_bytes(b"ElfFile\x00")
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "d.jsonl")
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert r["totals"]["files"] == 3
        assert [c["source"]["path"] for c in _read(out)][:1] == [os.path.join("evidence", "A.evtx")]

    def test_missing_input_is_clean_error(self, case, with_fake, tmp_path):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        from tools.artifacts import parse_windows_event_logs
        r = parse_windows_event_logs(str(case / "evidence" / "nope.evtx"),
                                     str(case / "analysis" / "x.jsonl"))
        assert r["success"] is False and "not found" in r["error"]

    def test_output_must_not_be_evidence(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        from tools.artifacts import parse_windows_event_logs
        with pytest.raises(ValueError):
            parse_windows_event_logs(str(case / "evidence"),
                                     str(case / "evidence" / "out.jsonl"))

    def test_deprecated_ez_alias_routes_native_and_writes_csv(self, case, tmp_path, with_fake):
        with_fake(fake_evtx_dump(tmp_path, [fx.evtx_record()]))
        import tools.eztools as ez
        with pytest.MonkeyPatch.context() as mp:
            called = {}
            mp.setattr(ez, "run_dotnet", lambda *a, **k: called.setdefault("dotnet", True))
            r = ez.ez_evtxecmd(str(case / "evidence"), str(case / "analysis"), "evtx.csv")
        assert "dotnet" not in called and "deprecated" in r
        csv_text = open(case / "analysis" / "evtx.csv").read()
        assert "EventId" in csv_text and "4624" in csv_text


class TestUnavailableBackend:
    def test_missing_binary_fails_fast_with_install_hint(self, case, monkeypatch):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", "/nonexistent/evtx_dump")
        pr._version_cache.clear()
        from tools.artifacts import parse_windows_event_logs
        r = parse_windows_event_logs(str(case / "evidence"), str(case / "analysis" / "x.jsonl"))
        pr._version_cache.clear()
        assert r["success"] is False and r["parser_unavailable"] is True
        assert r["artifact_type"] == "windows.evtx"
        assert "cargo install evtx" in r["install_hint"]


@needs_evtx_dump
class TestRealBinary:
    def test_version_probe_matches_pin(self):
        pr._version_cache.clear()
        version, err = pr.probe_version("evtx_dump")
        assert err is None and version.startswith("0.12")

    def test_corrupt_evtx_does_not_crash_the_server(self, case):
        """Deterministic malformed input: the tool must return a structured result,
        write no records, and never raise (a hostile file cannot take down MCP)."""
        from tools.artifacts import parse_windows_event_logs
        out = str(case / "analysis" / "corrupt.jsonl")
        (case / "evidence" / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\xAA" * 8192)
        r = parse_windows_event_logs(str(case / "evidence"), out)
        assert isinstance(r, dict)
        assert r["totals"]["records_written"] == 0
        assert r["parse_status"] in ("complete", "partial", "failed")
        assert os.path.exists(out)                      # created, empty, not corrupt state
