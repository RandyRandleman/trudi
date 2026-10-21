"""Backend registry: capability reporting, health checks, no silent substitution."""
import os
import stat
import textwrap

import pytest

from core import parsers as pr


@pytest.fixture(autouse=True)
def clear_cache():
    pr._version_cache.clear()
    yield
    pr._version_cache.clear()


def _stub(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


class TestCapabilities:
    def test_every_backend_reports_the_required_fields(self):
        cap = pr.capabilities()
        assert cap["schema_version"] == "trudi.artifact.v1"
        assert {r["parser"] for r in cap["backends"]} == {"evtx_dump", "trudi-prefetch", "chainsaw"}
        for r in cap["backends"]:
            for key in ("parser", "version", "artifact_types", "supported_format_versions",
                        "supports_recovery", "supports_offline_provider_templates",
                        "license", "limitations", "installed", "operational", "install_hint"):
                assert key in r, f"{r['parser']} missing {key}"

    def test_licenses_are_named(self):
        licenses = {r["parser"]: r["license"] for r in pr.capabilities()["backends"]}
        assert "GPL-3.0" in licenses["chainsaw"]
        assert "Apache-2.0" in licenses["trudi-prefetch"]
        assert "MIT" in licenses["evtx_dump"]

    def test_artifact_type_coverage_is_one_backend_each(self):
        seen = {}
        for r in pr.capabilities()["backends"]:
            for t in r["artifact_types"]:
                assert t not in seen, f"{t} claimed by two backends — ambiguous selection"
                seen[t] = r["parser"]
        assert set(seen) == {"windows.evtx", "windows.prefetch", "windows.srum"}

    def test_prefetch_limitations_name_the_unsupported_versions(self):
        rep = pr.backend_report("trudi_prefetch")
        assert any("17/23/26" in l for l in rep["limitations"])

    def test_evtx_advertises_recovery_and_offline_templates(self):
        rep = pr.backend_report("evtx_dump")
        assert rep["supports_recovery"] and rep["supports_offline_provider_templates"]


class TestResolutionAndHealth:
    def test_env_override_wins(self, tmp_path, monkeypatch):
        stub = _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            print("EVTX Parser 9.9.9")
        """)
        monkeypatch.setenv("TRUDI_EVTX_DUMP", stub)
        assert pr.resolve("evtx_dump") == stub
        assert pr.probe_version("evtx_dump")[0] == "9.9.9"

    def test_version_mismatch_with_pin_is_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            print("EVTX Parser 9.9.9")
        """))
        rep = pr.backend_report("evtx_dump")
        assert rep["operational"] and rep["version_matches_pin"] is False

    def test_unparseable_version_is_a_health_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            print("hello")
        """))
        rep = pr.backend_report("evtx_dump")
        assert rep["installed"] and not rep["operational"] and rep["health_error"]

    def test_missing_binary_reports_not_installed(self, monkeypatch):
        monkeypatch.setenv("TRUDI_CHAINSAW", "/nonexistent/chainsaw")
        rep = pr.backend_report("chainsaw")
        assert rep["installed"] is False and rep["operational"] is False

    def test_require_raises_structured_payload(self, monkeypatch):
        monkeypatch.setenv("TRUDI_PREFETCH_BIN", "/nonexistent/trudi-prefetch")
        with pytest.raises(pr.ParserUnavailable) as e:
            pr.require("trudi_prefetch", "windows.prefetch")
        payload = e.value.payload
        assert payload["parser_unavailable"] is True
        assert payload["artifact_type"] == "windows.prefetch"
        assert payload["env_override"] == "TRUDI_PREFETCH_BIN"
        assert payload["install_hint"]

    def test_version_probe_is_cached(self, tmp_path, monkeypatch):
        counter = tmp_path / "count"
        stub = _stub(tmp_path, "evtx_dump", f"""\
            #!/usr/bin/env python3
            open({str(counter)!r}, "a").write("x")
            print("EVTX Parser 0.12.2")
        """)
        monkeypatch.setenv("TRUDI_EVTX_DUMP", stub)
        pr.probe_version("evtx_dump")
        pr.probe_version("evtx_dump")
        assert len(counter.read_text()) == 1
        pr.probe_version("evtx_dump", refresh=True)
        assert len(counter.read_text()) == 2

    def test_probe_timeout_is_bounded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            import time; time.sleep(30)
        """))
        monkeypatch.setattr(pr, "PROBE_TIMEOUT", 1)
        version, err = pr.probe_version("evtx_dump")
        assert version is None and "timed out" in err


class TestNameCollision:
    """Regression: python-evtx installs a script ALSO called `evtx_dump` into the
    venv, which sat earlier on PATH than the Rust parser and made the backend
    report unhealthy. Candidates must be version-probed, not trusted by name."""

    def test_shadowing_binary_on_path_is_skipped(self, tmp_path, monkeypatch):
        shadow_dir = tmp_path / "venv-bin"
        shadow_dir.mkdir()
        _stub(shadow_dir, "evtx_dump", """\
            #!/usr/bin/env python3
            import sys
            print("usage: evtx_dump <file>"); sys.exit(2)
        """)
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        real = _stub(real_dir, "evtx_dump", """\
            #!/usr/bin/env python3
            print("EVTX Parser 0.12.2")
        """)
        monkeypatch.delenv("TRUDI_EVTX_DUMP", raising=False)
        # NOTE: PATH is left intact — the stubs are `#!/usr/bin/env python3`.
        # The shadowing order is expressed through _candidates directly.
        monkeypatch.setattr(pr, "_candidates",
                            lambda key: [str(shadow_dir / "evtx_dump"), real])
        rep = pr.backend_report("evtx_dump")
        assert rep["operational"] is True
        assert rep["binary"] == real and rep["version"] == "0.12.2"

    def test_all_candidates_bad_reports_the_last_error(self, tmp_path, monkeypatch):
        bad = _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            print("not a parser")
        """)
        monkeypatch.delenv("TRUDI_EVTX_DUMP", raising=False)
        monkeypatch.setattr(pr, "_candidates", lambda key: [bad])
        rep = pr.backend_report("evtx_dump")
        assert rep["operational"] is False
        assert "did not identify itself" in rep["health_error"]


class TestNoSilentSubstitution:
    def test_registry_has_no_fallback_chain(self):
        """A backend never names another backend as an automatic replacement."""
        for key, be in pr.BACKENDS.items():
            others = {k for k in pr.BACKENDS if k != key}
            assert not (set(be.extra.get("fallbacks", [])) & others)

    def test_parser_name_travels_with_every_result(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_EVTX_DUMP", _stub(tmp_path, "evtx_dump", """\
            #!/usr/bin/env python3
            print("EVTX Parser 0.12.2")
        """))
        path, version = pr.require("evtx_dump", "windows.evtx")
        assert os.path.exists(path) and version == "0.12.2"
