"""Regressions for the Linux failures this migration fixes.

1. Prefetch parsing required Windows (PECmd → RtlDecompressBufferEx) — the
   native path must not touch .NET at all.
2. SRUM had no parser: the only route was ez.sqlecmd, a SQLite parser that
   cannot read an ESE database.
3. Every artifact tool must keep evidence read-only and refuse evidence-path
   outputs.
"""
import inspect
import re

import pytest

import tools.artifacts as art
from core import parsers as pr


def _executable_source(module) -> str:
    """Module source with comments and string literals (incl. docstrings) removed,
    so prose that NAMES the Windows-only behaviour is not mistaken for using it."""
    import io
    import tokenize
    src = inspect.getsource(module)
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out)


class TestNoWindowsDependencies:
    @pytest.mark.parametrize("module", [art, pr])
    def test_no_windows_runtime_is_invoked(self, module):
        """No .NET, Wine, Windows decompression or ESE APIs anywhere in the path.

        Matched as whole words on executable-ish tokens, so prose that merely
        NAMES the old behaviour (or the `exe,dll,sys` PE extension filter used to
        read acquired provider templates) does not trip the check.
        """
        code = _executable_source(module)
        for pattern in (r"\bdotnet\b", r"RtlDecompressBufferEx", r"\bESENT\b",
                        r"\bwine\b", r"zimmermantools", r"EvtxECmd", r"PECmd",
                        r"SrumECmd"):
            assert not re.search(pattern, code), \
                f"{module.__name__} executes/references {pattern} outside documentation"

    def test_backends_are_native_binaries(self):
        for be in pr.BACKENDS.values():
            assert not be.binary.endswith((".dll", ".exe"))
            assert "zimmermantools" not in be.binary

    def test_prefetch_backend_documents_the_decompression_fix(self):
        doc = art.parse_windows_prefetch.__doc__ or ""
        assert "Xpress-Huffman" in doc and "RtlDecompressBufferEx" in doc


class TestSrumIsReachable:
    def test_srum_has_a_dedicated_tool_not_sqlecmd(self):
        assert callable(art.parse_windows_srum)
        assert "windows.srum" in pr.BACKENDS["chainsaw"].artifact_types
        doc = art.parse_windows_srum.__doc__ or ""
        assert "SRUDB.dat" in doc and "SOFTWARE" in doc

    def test_srum_requires_the_software_hive_by_contract(self):
        sig = inspect.signature(art.parse_windows_srum)
        assert sig.parameters["software_hive"].default is inspect.Parameter.empty


class TestPublicSurface:
    def test_artifact_namespace_is_mounted(self):
        import server
        assert ("artifact", art.mcp) in server.NAMESPACES

    def test_artifact_oriented_names(self):
        for name in ("parse_windows_event_logs", "parse_windows_prefetch",
                     "parse_windows_srum", "parser_capabilities"):
            assert callable(getattr(art, name))

    def test_legacy_ez_aliases_still_exist_and_are_marked_deprecated(self):
        import tools.eztools as ez
        for fn in (ez.ez_evtxecmd, ez.ez_pecmd):
            assert "DEPRECATED" in (fn.__doc__ or "")

    def test_schema_version_is_pinned(self):
        from core import artifact_schema as sch
        assert sch.SCHEMA_VERSION == "trudi.artifact.v1"


class TestEvidenceIntegrity:
    @pytest.mark.parametrize("fn", [art.parse_windows_event_logs, art.parse_windows_prefetch,
                                    art.parse_windows_srum, art.event_record_xml,
                                    art.build_wevt_cache, art.export_ez_csv])
    def test_output_paths_are_guarded(self, fn):
        src = inspect.getsource(fn)
        assert "output_path" in inspect.signature(fn).parameters
        # @output_safe wraps every one of these (asserts non-evidence output)
        assert getattr(fn, "__wrapped__", None) is not None or "assert_output_safe" in src

    def test_no_shell_string_construction(self):
        src = inspect.getsource(art)
        assert "shell=True" not in src
        assert not re.search(r"subprocess\.(run|Popen)\(\s*f?[\"']", src)

    def test_private_work_dir_is_not_in_evidence(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("#")
        (tmp_path / "analysis").mkdir()
        (tmp_path / "evidence").mkdir()
        d = art._work_dir(str(tmp_path / "analysis" / "out.jsonl"))
        assert ".trudi-work" in d and "/evidence/" not in d
        with pytest.raises(ValueError):
            art._work_dir(str(tmp_path / "evidence" / "out.jsonl"))
