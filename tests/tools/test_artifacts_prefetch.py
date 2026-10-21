"""Prefetch: integration against the real Rust helper + normalization units.

The integration tests run the actual `trudi-prefetch` binary over synthetic SCCA
fixtures — they are the regression tests for the Linux failure they replace
(PECmd cannot decompress Win8+ prefetch off Windows, and needs .NET at all).
"""
import json
import os
import shutil
import subprocess

import pytest

from core import parsers as pr
from tests.fixtures import artifact_fixtures as fx

BIN = (os.environ.get("TRUDI_PREFETCH_BIN")
       or shutil.which("trudi-prefetch")
       or os.path.join(os.path.dirname(__file__), "..", "..",
                       "rust", "trudi-prefetch", "target", "release", "trudi-prefetch"))
BIN = os.path.abspath(BIN)
needs_bin = pytest.mark.skipif(
    not (os.path.isfile(BIN) and os.access(BIN, os.X_OK)),
    reason="trudi-prefetch not built (cargo build --release --manifest-path rust/trudi-prefetch/Cargo.toml)",
)


@pytest.fixture
def case(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# case")
    for d in ("evidence", "analysis"):
        (tmp_path / d).mkdir()
    return tmp_path


@pytest.fixture
def use_real_binary(monkeypatch):
    monkeypatch.setenv("TRUDI_PREFETCH_BIN", BIN)
    pr._version_cache.clear()
    yield
    pr._version_cache.clear()


def _write_pf(case, name: str, payload: bytes) -> str:
    p = case / "evidence" / name
    p.write_bytes(payload)
    return str(p)


@needs_bin
class TestHelperCli:
    def test_version_json_reports_capabilities(self):
        out = subprocess.run([BIN, "--version-json"], capture_output=True, text=True, timeout=30)
        meta = json.loads(out.stdout)
        assert meta["parser"] == "prefetch-core"
        assert meta["supported_format_versions"] == [30, 31]
        assert meta["supports_compressed_mam"] is True
        assert "file_metrics_array" in meta["unsupported_sections"]

    def test_no_args_is_usage_error(self):
        assert subprocess.run([BIN], capture_output=True).returncode == 2

    def test_directory_ordering_is_deterministic(self, case):
        for n in ("B.EXE-00000002.pf", "A.EXE-00000001.pf", "C.EXE-00000003.pf"):
            _write_pf(case, n, fx.build_scca(executable=n.split("-")[0]))
        runs = []
        for _ in range(2):
            out = subprocess.run([BIN, str(case / "evidence")], capture_output=True, text=True, timeout=60)
            runs.append([json.loads(l)["file_name"] for l in out.stdout.splitlines()])
        assert runs[0] == runs[1] == sorted(runs[0])

    def test_symlink_is_not_followed(self, case, tmp_path):
        real = _write_pf(case, "REAL.EXE-0000000A.pf", fx.build_scca())
        link = tmp_path / "link.pf"
        link.symlink_to(real)
        out = subprocess.run([BIN, str(link)], capture_output=True, text=True, timeout=30)
        assert out.returncode == 2 and "symlink" in out.stderr

    def test_oversize_file_rejected_without_reading(self, case):
        p = _write_pf(case, "BIG.EXE-0000000B.pf", fx.build_scca())
        out = subprocess.run([BIN, "--max-bytes", "10", p], capture_output=True, text=True, timeout=30)
        rec = json.loads(out.stdout.splitlines()[0])
        assert rec["status"] == "error" and rec["error"]["kind"] == "too_large"


@needs_bin
class TestParseWindowsPrefetch:
    def test_valid_v30_normalizes(self, case, use_real_binary):
        _write_pf(case, "COREUPDATER.EXE-157C54BB.pf", fx.build_scca(run_count=3))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "prefetch.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        assert r["success"] and r["totals"]["parsed"] == 1 and r["parse_status"] == "complete"
        rec = json.loads(open(out).read().splitlines()[0])
        from core.artifact_schema import validate_record
        assert validate_record(rec) == []
        d = rec["data"]
        assert d["executable"] == "COREUPDATER.EXE"
        assert d["run_count"] == 3
        assert d["format_version"] == 30
        assert d["prefetch_hash_from_filename"] == "157C54BB"
        assert d["last_run_times_utc"][0] == "2020-09-19T03:40:49.410320Z"
        assert d["volumes"][0]["serial_number_hex"] == "B0E0E8FF"
        assert d["referenced_filename_count"] == 2
        assert rec["source"]["sha256"] and rec["source"]["path"].startswith("evidence")
        assert rec["parser"]["name"] == "trudi-prefetch"

    def test_multiple_run_times_preserved(self, case, use_real_binary):
        times = [fx.FILETIME_2020_09_19 - i * 10**9 for i in range(8)]
        _write_pf(case, "A.EXE-00000001.pf", fx.build_scca(run_times=times))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "p.jsonl")
        parse_windows_prefetch(str(case / "evidence"), out)
        rec = json.loads(open(out).read().splitlines()[0])
        assert len(rec["data"]["last_run_times_utc"]) == 8
        assert rec["timestamps"]["last_run_utc"] == rec["data"]["last_run_times_utc"][0]

    def test_multiple_volumes(self, case, use_real_binary):
        vols = [(r"\VOLUME{01d1-aaaa}", 0xAAAA1111, fx.FILETIME_2020_09_19),
                (r"\VOLUME{01d2-bbbb}", 0xBBBB2222, fx.FILETIME_2020_09_19)]
        _write_pf(case, "M.EXE-00000002.pf", fx.build_scca(volumes=vols))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "m.jsonl")
        parse_windows_prefetch(str(case / "evidence"), out)
        rec = json.loads(open(out).read().splitlines()[0])
        assert [v["serial_number_hex"] for v in rec["data"]["volumes"]] == ["AAAA1111", "BBBB2222"]

    @pytest.mark.parametrize("version", [17, 23, 26, 99])
    def test_unsupported_versions_fail_loudly(self, case, use_real_binary, version):
        _write_pf(case, f"OLD{version}.EXE-00000003.pf", fx.build_scca(version=version))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / f"v{version}.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        assert r["parse_status"] == "failed"
        assert r["failures_by_kind"] == {"unsupported_version": 1}
        rec = json.loads(open(out).read().splitlines()[0])
        assert rec["parse_status"] == "failed"
        assert str(version) in rec["data"]["error"]["detail"]

    @pytest.mark.parametrize("name,payload,kind", [
        ("TRUNC.EXE-00000004.pf", fx.build_scca()[:40], "too_short"),
        ("BADSIG.EXE-00000005.pf", fx.build_scca(signature=b"NOPE"), "bad_signature"),
        ("MAM.EXE-00000006.pf", fx.build_mam_header_only(), "decompress_failed"),
    ])
    def test_corrupt_inputs_are_structured_errors(self, case, use_real_binary, name, payload, kind):
        _write_pf(case, name, payload)
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "bad.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        assert r["failures_by_kind"] == {kind: 1}

    def test_malformed_utf16_name_does_not_crash(self, case, use_real_binary):
        _write_pf(case, "UTF.EXE-00000007.pf", fx.build_scca(malformed_utf16=True))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "u.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        assert r["success"]

    def test_invalid_filename_offset_is_survived(self, case, use_real_binary):
        _write_pf(case, "OFF.EXE-00000008.pf", fx.build_scca(break_filename_offset=True))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "o.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        rec = json.loads(open(out).read().splitlines()[0])
        assert r["success"] and rec["data"]["referenced_filename_count"] == 0

    def test_mixed_corpus_is_partial_not_fatal(self, case, use_real_binary):
        _write_pf(case, "GOOD.EXE-00000009.pf", fx.build_scca())
        _write_pf(case, "BAD.EXE-0000000A.pf", fx.build_scca(version=23))
        from tools.artifacts import parse_windows_prefetch
        out = str(case / "analysis" / "mix.jsonl")
        r = parse_windows_prefetch(str(case / "evidence"), out)
        assert r["parse_status"] == "partial"
        assert r["totals"] == {"files": 2, "parsed": 1, "failed": 1}

    def test_output_into_evidence_is_refused(self, case, use_real_binary):
        _write_pf(case, "X.EXE-0000000B.pf", fx.build_scca())
        from tools.artifacts import parse_windows_prefetch
        with pytest.raises(ValueError):
            parse_windows_prefetch(str(case / "evidence"),
                                   str(case / "evidence" / "out.jsonl"))

    def test_ez_csv_export_layer(self, case, use_real_binary):
        _write_pf(case, "COREUPDATER.EXE-157C54BB.pf", fx.build_scca())
        from tools.artifacts import parse_windows_prefetch, export_ez_csv
        out = str(case / "analysis" / "p.jsonl")
        parse_windows_prefetch(str(case / "evidence"), out)
        csv_path = str(case / "analysis" / "p.csv")
        r = export_ez_csv(out, csv_path, layout="prefetch")
        text = open(csv_path).read()
        assert r["rows"] == 1
        assert "ExecutableName" in text and "COREUPDATER.EXE" in text

    def test_deprecated_ez_pecmd_alias_uses_native_backend(self, case, use_real_binary):
        _write_pf(case, "COREUPDATER.EXE-157C54BB.pf", fx.build_scca())
        import tools.eztools as ez
        with pytest.MonkeyPatch.context() as mp:
            called = {}
            mp.setattr(ez, "run_dotnet", lambda *a, **k: called.setdefault("dotnet", True))
            r = ez.ez_pecmd(str(case / "evidence"), str(case / "analysis"), "prefetch.csv")
        assert "dotnet" not in called                       # no .NET on the native path
        assert r["success"] and "deprecated" in r
        assert os.path.exists(str(case / "analysis" / "prefetch.csv"))
        assert os.path.exists(str(case / "analysis" / "prefetch.jsonl"))


class TestNormalizationUnits:
    """No binary needed: adapter behaviour over parser-shaped input."""

    def _norm(self, rec, tmp_path):
        from tools.artifacts import _normalize_prefetch
        f = tmp_path / "x.pf"
        f.write_bytes(b"x")
        return _normalize_prefetch(rec, str(f), "c" * 64,
                                   {"name": "trudi-prefetch", "version": "0.1.0",
                                    "adapter_version": "1.0.0"})

    def test_error_record_marks_failed_and_keeps_raw(self, tmp_path):
        rec = self._norm({"status": "error", "error": {"kind": "bad_signature", "detail": "nope"},
                          "warnings": []}, tmp_path)
        assert rec["parse_status"] == "failed"
        assert rec["raw"]["error"]["kind"] == "bad_signature"
        assert rec["warnings"][0]["code"] == "bad_signature"

    def test_unsupported_sections_are_carried(self, tmp_path):
        rec = self._norm({"status": "complete", "data": {"filenames": [], "filename_count": 0},
                          "unsupported_sections": ["trace_chain_array"]}, tmp_path)
        assert rec["data"]["unsupported_sections"] == ["trace_chain_array"]

    def test_parser_warnings_downgrade_to_partial(self, tmp_path):
        rec = self._norm({"status": "complete", "warnings": ["executable name was empty"],
                          "data": {"filenames": [], "filename_count": 0}}, tmp_path)
        assert rec["parse_status"] == "partial"
