"""Linux-native parser backend registry, capability reporting, and health checks.

TRUDI's artifact tools never guess which parser is present: each backend is
resolved by an explicit path (env-overridable), version-probed once per process,
and reported through `capabilities()`. A missing backend fails fast with a
structured error naming the artifact type, the expected binary, and how to
install it — never a silent substitution.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

PROBE_TIMEOUT = 20


@dataclass(frozen=True)
class Backend:
    name: str
    binary: str                      # default executable name/path
    env_var: str                     # override, e.g. TRUDI_EVTX_DUMP
    artifact_types: tuple[str, ...]
    license: str
    pinned_version: str              # version the packaging installs
    version_args: tuple[str, ...]
    version_pattern: str             # regex with one capture group
    supports_recovery: bool = False
    supports_offline_templates: bool = False
    supported_format_versions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    install_hint: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


BACKENDS: dict[str, Backend] = {
    "evtx_dump": Backend(
        name="evtx_dump",
        binary="evtx_dump",
        env_var="TRUDI_EVTX_DUMP",
        artifact_types=("windows.evtx",),
        license="MIT OR Apache-2.0 (omerbenamram/evtx)",
        pinned_version="0.12.2",
        version_args=("--version",),
        version_pattern=r"(\d+\.\d+\.\d+)",
        supports_recovery=True,          # --validate-checksums off ⇒ dirty chunks parsed
        supports_offline_templates=True,  # --wevt-cache / extract-wevt-templates
        supported_format_versions=("EVTX 3.x",),
        limitations=(
            "Provider message strings are only rendered when the embedded template "
            "or a supplied .wevtcache covers the provider; structured EventData is "
            "always authoritative.",
        ),
        install_hint="cargo install evtx --version 0.12.2 --locked  (installs evtx_dump)",
    ),
    "trudi_prefetch": Backend(
        name="trudi-prefetch",
        binary="trudi-prefetch",
        env_var="TRUDI_PREFETCH_BIN",
        artifact_types=("windows.prefetch",),
        license="MIT (helper) over Apache-2.0 (prefetch-core)",
        pinned_version="0.1.0",
        version_args=("--version",),
        version_pattern=r"trudi-prefetch (\d+\.\d+\.\d+)",
        supports_recovery=False,
        supported_format_versions=("SCCA 30 (Win10)", "SCCA 31 (Win11)"),
        limitations=(
            "SCCA versions 17/23/26 (XP/Vista/7/8.1) are NOT supported — such files "
            "return a structured unsupported_version error, never a partial guess.",
            "File-metrics, trace-chain, MFT entry/sequence and directory-string "
            "sections are not decoded; every record names them in unsupported_sections.",
            "The prefetch hash is taken from the file NAME, not the file body.",
        ),
        install_hint="cargo build --release --manifest-path rust/trudi-prefetch/Cargo.toml",
    ),
    "chainsaw": Backend(
        name="chainsaw",
        binary="chainsaw",
        env_var="TRUDI_CHAINSAW",
        artifact_types=("windows.srum",),
        license="GPL-3.0-only (WithSecureLabs/chainsaw) — invoked as a separate, "
                "unmodified binary; not linked into or vendored by TRUDI",
        pinned_version="2.10.2",         # release tag; the binary self-reports 2.10.1
        version_args=("--version",),
        version_pattern=r"chainsaw (\d+\.\d+\.\d+)",
        supports_recovery=False,
        supported_format_versions=("SRUDB.dat (ESE) as supported by chainsaw 2.10.x",),
        limitations=(
            "Requires the matching SOFTWARE hive to resolve provider GUIDs to table "
            "meanings; without it TRUDI returns an incomplete-input error.",
            "A dirty/uncommitted ESE database is reported as-is — TRUDI never "
            "recovers or replays transaction logs into the evidence.",
            "Release tag v2.10.2 ships a binary that self-reports 2.10.1.",
        ),
        install_hint="install the pinned chainsaw release binary (see docs/linux-native-parsers.md)",
    ),
}

#: key -> (resolved_path | None, version | None, error | None)
_version_cache: dict[str, tuple[str | None, str | None, str | None]] = {}


class ParserUnavailable(RuntimeError):
    """Raised when a required backend is missing or unhealthy."""

    def __init__(self, payload: dict[str, Any]):
        super().__init__(payload.get("error", "parser unavailable"))
        self.payload = payload


def _candidates(key: str) -> list[str]:
    """Every plausible path for a backend, in preference order.

    Explicit install locations come BEFORE a PATH lookup on purpose: an
    unrelated program can share the name (the python-evtx package installs a
    script also called `evtx_dump` into the venv, which would otherwise shadow
    the Rust parser). Each candidate is version-probed, and one that does not
    identify itself correctly is skipped rather than reported as broken.
    """
    be = BACKENDS[key]
    out: list[str] = []
    override = os.environ.get(be.env_var)
    if override:
        return [override]                     # explicit choice is never second-guessed
    for cand in (f"/usr/local/bin/{be.binary}", f"/opt/trudi/bin/{be.binary}"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            out.append(cand)
    found = shutil.which(be.binary)
    if found and found not in out:
        out.append(found)
    return out


def _probe(path: str, be: Backend) -> tuple[str | None, str | None]:
    """(version, error) for one candidate path."""
    try:
        proc = subprocess.run(
            [path, *be.version_args],
            capture_output=True, timeout=PROBE_TIMEOUT, check=False,
        )
        text = (proc.stdout or b"").decode("utf-8", "replace") + \
               (proc.stderr or b"").decode("utf-8", "replace")
        m = re.search(be.version_pattern, text)
        if m:
            return m.group(1), None
        return None, (f"{path} did not identify itself as {be.name} "
                      f"(`{os.path.basename(path)} {' '.join(be.version_args)}` "
                      f"printed no matching version)")
    except subprocess.TimeoutExpired:
        return None, f"{path} --version timed out after {PROBE_TIMEOUT}s"
    except OSError as e:
        return None, f"{path} failed to execute: {e}"


def _resolve_and_probe(key: str, *, refresh: bool = False
                       ) -> tuple[str | None, str | None, str | None]:
    """(path, version, error). Probes each candidate and keeps the first that
    identifies itself as this backend. Cached per process."""
    if not refresh and key in _version_cache:
        return _version_cache[key]
    be = BACKENDS[key]
    cands = _candidates(key)
    if not cands:
        result = (None, None,
                  f"{be.binary} not found (set {be.env_var} or install it)")
        _version_cache[key] = result
        return result
    last_err = None
    for path in cands:
        version, err = _probe(path, be)
        if version:
            _version_cache[key] = (path, version, None)
            return _version_cache[key]
        last_err = err
    result = (cands[0], None, last_err)
    _version_cache[key] = result
    return result


def resolve(key: str) -> str | None:
    """Absolute path to the backend's executable (validated), or None."""
    path, version, _err = _resolve_and_probe(key)
    return path if version else (path if path and os.path.isfile(path) else None)


def probe_version(key: str, *, refresh: bool = False) -> tuple[str | None, str | None]:
    """(version, error) — kept for callers that only care about the version."""
    _path, version, err = _resolve_and_probe(key, refresh=refresh)
    return version, err


def require(key: str, artifact_type: str) -> tuple[str, str]:
    """(path, version) for a healthy backend, else raise ParserUnavailable.

    Fails early and loudly: no fallback parser is substituted behind the
    caller's back. If a caller ever implements a fallback, it must record the
    selected parser in the result and emit an explicit fallback warning.
    """
    be = BACKENDS[key]
    path, version, err = _resolve_and_probe(key)
    if not path or not version:
        raise ParserUnavailable({
            "success": False,
            "parser_unavailable": True,
            "artifact_type": artifact_type,
            "parser": be.name,
            "expected_binary": be.binary,
            "env_override": be.env_var,
            "pinned_version": be.pinned_version,
            "error": (
                f"No Linux-native parser available for {artifact_type}: "
                f"{err or (be.binary + ' not found')}"
            ),
            "install_hint": be.install_hint,
        })
    return path, version


def backend_report(key: str) -> dict[str, Any]:
    be = BACKENDS[key]
    path, version, err = _resolve_and_probe(key)
    return {
        "parser": be.name,
        "binary": path or be.binary,
        "installed": bool(path and os.path.isfile(path)),
        "candidates_checked": _candidates(key),
        "operational": bool(path and not err),
        "version": version,
        "pinned_version": be.pinned_version,
        "version_matches_pin": bool(version) and version == be.pinned_version,
        "artifact_types": list(be.artifact_types),
        "supported_format_versions": list(be.supported_format_versions),
        "supports_recovery": be.supports_recovery,
        "supports_offline_provider_templates": be.supports_offline_templates,
        "license": be.license,
        "limitations": list(be.limitations),
        "health_error": err,
        "install_hint": be.install_hint,
    }


def capabilities() -> dict[str, Any]:
    """Full capability report for every registered backend."""
    reports = [backend_report(k) for k in BACKENDS]
    return {
        "success": True,
        "schema_version": "trudi.artifact.v1",
        "platform": "linux-native (no .NET, no Wine, no Windows APIs)",
        "backends": reports,
        "operational": [r["parser"] for r in reports if r["operational"]],
        "unavailable": [r["parser"] for r in reports if not r["operational"]],
    }
