"""Canonical schema: construction, validation, timestamp + path normalization."""
import json
import os

import pytest

from core import artifact_schema as sch


def _rec(**over):
    base = dict(
        artifact_type=sch.ARTIFACT_EVTX,
        source={"path": "evidence/x.evtx", "absolute_path": "/cases/C/evidence/x.evtx",
                "case_root": "/cases/C", "sha256": "a" * 64, "size": 10},
        parser={"name": "evtx_dump", "version": "0.12.2", "adapter_version": "1.0.0"},
        data={"event_id": 4624},
    )
    base.update(over)
    return sch.make_record(**base)


class TestMakeAndValidate:
    def test_valid_record_has_no_problems(self):
        assert sch.validate_record(_rec()) == []

    def test_schema_version_is_stamped(self):
        assert _rec()["schema_version"] == "trudi.artifact.v1"

    def test_raw_and_data_are_separate(self):
        r = _rec(data={"event_id": 1}, raw={"Event": {"System": {}}})
        assert r["data"] != r["raw"] and r["raw"]["Event"]["System"] == {}

    def test_invalid_parse_status_rejected(self):
        with pytest.raises(ValueError):
            _rec(parse_status="mostly")

    @pytest.mark.parametrize("missing", ["schema_version", "parser", "warnings", "recovered"])
    def test_missing_keys_are_reported(self, missing):
        r = _rec()
        del r[missing]
        assert any(missing in p for p in sch.validate_record(r))

    def test_absolute_source_path_with_case_root_is_rejected(self):
        r = _rec()
        r["source"]["path"] = "/cases/C/evidence/x.evtx"
        assert any("evidence-relative" in p for p in sch.validate_record(r))

    def test_short_sha_rejected(self):
        r = _rec()
        r["source"]["sha256"] = "abc"
        assert any("sha256" in p for p in sch.validate_record(r))

    def test_parser_version_required(self):
        r = _rec()
        r["parser"]["version"] = ""
        assert any("parser.version" in p for p in sch.validate_record(r))

    def test_warning_shape_enforced(self):
        r = _rec(warnings=[{"code": "x"}])
        assert any("code and message" in p for p in sch.validate_record(r))

    def test_records_are_json_serializable(self):
        json.loads(json.dumps(_rec(), default=str))


class TestFiletime:
    def test_known_value(self):
        assert sch.filetime_to_utc(132449604494103203) == "2020-09-19T03:40:49.410320Z"

    @pytest.mark.parametrize("bad", [0, None, -5, 1])
    def test_invalid_values_return_none(self, bad):
        assert sch.filetime_to_utc(bad) is None


class TestSourceBlock:
    def test_path_is_case_relative(self, tmp_path):
        case = tmp_path / "CASE-1"
        (case / "evidence").mkdir(parents=True)
        (case / "analysis").mkdir()
        (case / "CLAUDE.md").write_text("# case")
        ev = case / "evidence" / "Security.evtx"
        ev.write_bytes(b"x" * 10)
        block = sch.source_block(str(ev), sha256="b" * 64)
        assert block["path"] == os.path.join("evidence", "Security.evtx")
        assert block["case_root"] == str(case)
        assert block["absolute_path"] == str(ev)
        assert block["size"] == 10

    def test_outside_case_falls_back_to_basename(self, tmp_path):
        f = tmp_path / "loose.pf"
        f.write_bytes(b"x")
        assert sch.source_block(str(f))["path"] == "loose.pf"

    def test_sha256_matches_hashlib(self, tmp_path):
        import hashlib
        f = tmp_path / "a.bin"
        f.write_bytes(b"trudi")
        assert sch.sha256_file(str(f)) == hashlib.sha256(b"trudi").hexdigest()
