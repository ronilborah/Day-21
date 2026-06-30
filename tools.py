"""tools.py

Tool registry for agent-prober (Team 4 — F4 Active Scan, safe/non-exploit tier).

Each tool wrapper exposes a uniform .run(target: str, context: dict) -> dict interface.
When TOOL_MOCK_MODE=true (or the binary is missing), wrappers return a realistic
canned JSON payload instead of shelling out — this lets you develop and demo the
FastAPI layer without needing every binary installed, and keeps you from ever
touching a target that isn't explicitly approved.

Real-mode execution only ever runs against the `target` string the caller supplied
in the request body — it is the caller's responsibility (per Section 9 of the
assignment) to only pass instructor-approved lab targets.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any

MOCK_MODE = os.environ.get("TOOL_MOCK_MODE", "true").lower() == "true"
TOOL_TIMEOUT_SECONDS = int(os.environ.get("TOOL_TIMEOUT_SECONDS", "300"))


class ToolWrapper(ABC):
    """Base class for a single CLI tool wrapper."""

    tool_key: str = "base"
    family_id: str = "F4"

    @abstractmethod
    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        """Return the argv list to execute for this tool against target."""

    @abstractmethod
    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        """Return a realistic canned result for mock/demo mode."""

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        """Default passthrough parser — subclasses override for structured parsing."""
        return {
            "tool_name": self.tool_key,
            "family_id": self.family_id,
            "target": target,
            "raw_stdout": raw_stdout[-4000:],  # keep responses bounded
            "raw_stderr": raw_stderr[-1000:] if raw_stderr else "",
            "errors": [],
        }

    def run(self, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        cmd = self.build_command(target, context)
        binary = cmd[0]

        if MOCK_MODE or shutil.which(binary) is None:
            result = self.mock_output(target, context)
            result["mock"] = True
            return result

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT_SECONDS,
            )
            result = self.parse_output(proc.stdout, proc.stderr, target)
            result["mock"] = False
            result["return_code"] = proc.returncode
            return result
        except subprocess.TimeoutExpired:
            return {
                "tool_name": self.tool_key,
                "family_id": self.family_id,
                "target": target,
                "errors": [f"{self.tool_key} timed out after {TOOL_TIMEOUT_SECONDS}s"],
                "mock": False,
            }
        except FileNotFoundError:
            result = self.mock_output(target, context)
            result["mock"] = True
            result["errors"] = [f"{binary} not found on PATH; returned mock output"]
            return result


# ---------------------------------------------------------------------------
# F1 shared tool
# ---------------------------------------------------------------------------

class HttpxWrapper(ToolWrapper):
    """WARNING — binary name collision: the Python `httpx` pip package installs
    its own CLI shim at the same `httpx` name on PATH (it's an HTTP client
    library, not ProjectDiscovery's recon tool). That shim exits 0 even when it
    can't actually run, so a naive return-code check would silently treat
    garbage as a successful scan. This wrapper validates that stdout actually
    parses as the real tool's JSON-lines output before trusting it; if it
    can't, it reports an explicit error pointing at the collision instead of
    fabricating recon data. On a real machine, run `httpx -version` and check
    it mentions "projectdiscovery" before trusting `shutil.which('httpx')`.
    """

    tool_key = "httpx"
    family_id = "F1"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        return ["httpx", "-u", target, "-silent", "-json", "-status-code", "-title", "-tech-detect"]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = {
            "tool_name": "httpx",
            "family_id": "F1",
            "target": target,
            "live": False,
            "status_code": None,
            "title": None,
            "tech": [],
            "errors": [],
        }

        json_lines = []
        for line in raw_stdout.strip().splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                json_lines.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not json_lines:
            result["errors"].append(
                "httpx produced no parseable JSON lines. This usually means the "
                "wrong 'httpx' binary is on PATH (the Python httpx pip package "
                "installs a same-named but unrelated CLI). Run 'httpx -version' "
                "and confirm it is ProjectDiscovery's tool, not the Python library shim. "
                f"Raw output was: {raw_stdout[:200]!r}"
            )
            return result

        entry = json_lines[0]
        result["live"] = True
        result["status_code"] = entry.get("status_code")
        result["title"] = entry.get("title")
        result["tech"] = entry.get("tech", [])
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "httpx",
            "family_id": "F1",
            "target": target,
            "live": True,
            "status_code": 200,
            "title": "Mock Target",
            "tech": ["nginx"],
            "errors": [],
        }


# ---------------------------------------------------------------------------
# F4 (safe) tools — Team 4 Prober allowlist
# ---------------------------------------------------------------------------

class NucleiActiveWrapper(ToolWrapper):
    tool_key = "nuclei_active"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        return ["nuclei", "-u", target, "-jsonl", "-silent",
                "-t", "http/vulnerabilities/", "-t", "http/misconfiguration/"]

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "nuclei_active",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["missing_security_headers"],
            "findings": [
                {"template": "missing-csp-header", "severity": "info",
                 "matched_at": target, "description": "No Content-Security-Policy header found"}
            ],
            "errors": [],
        }


class TestsslDeepWrapper(ToolWrapper):
    """testssl.sh's --jsonfile-pretty flag, like corsy's -o, writes to a real
    file path — "-" is treated as a literal filename, NOT stdout (confirmed:
    running with "-" produces 'Fatal error: non-empty "-" exists'). This
    wrapper writes to a temp file and reads it back.

    Real output schema (confirmed against a live scan): top-level
    'scanResult' is a list. Most entries are flat {id, severity, finding}
    pretest/DNS checks; the actual per-target results are in an entry with a
    'targetHost' key, containing nested category lists — protocols, ciphers,
    vulnerabilities, headerResponse, etc. — each itself a list of
    {id, severity, finding} dicts. We pull 'protocols' (weak TLS versions)
    and 'vulnerabilities' as the signal-relevant categories.
    """

    tool_key = "testssl_deep"
    family_id = "F4"
    _last_outfile: str = ""

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json", prefix="testssl_")
        os.close(fd)
        os.remove(path)
        self._last_outfile = path
        # testssl.sh wants host:port, not a full URL
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        if ":" not in host:
            host = f"{host}:443"
        return ["testssl.sh", "--quiet", "--jsonfile-pretty", path, host]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = {
            "tool_name": "testssl_deep",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }
        try:
            with open(self._last_outfile) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            result["errors"].append(f"testssl.sh output file unreadable: {exc}")
            return result
        finally:
            if os.path.exists(self._last_outfile):
                os.remove(self._last_outfile)

        scan_results = data.get("scanResult") or []
        target_entry = next((e for e in scan_results if isinstance(e, dict) and "targetHost" in e), None)
        if target_entry is None:
            result["errors"].append("no per-target entry found in scanResult")
            return result

        weak_tls_ids = {"SSLv2", "SSLv3", "TLS1", "TLS1_1"}
        for proto in target_entry.get("protocols") or []:
            if proto.get("id") in weak_tls_ids and "not offered" not in proto.get("finding", "").lower():
                result["findings"].append({"id": proto["id"], "severity": proto.get("severity"),
                                            "finding": proto.get("finding")})
                result["signal_candidates"].append("weak_tls_version_or_ciphers")

        for vuln in target_entry.get("vulnerabilities") or []:
            sev = (vuln.get("severity") or "").upper()
            if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                result["findings"].append({"id": vuln.get("id"), "severity": sev,
                                            "finding": vuln.get("finding")})
                result["signal_candidates"].append("weak_tls_version_or_ciphers")

        result["signal_candidates"] = sorted(set(result["signal_candidates"]))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "testssl_deep",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["weak_tls_version_or_ciphers"],
            "findings": [
                {"id": "TLS1", "severity": "LOW", "finding": "TLS 1.0 offered"},
                {"id": "TLS1_1", "severity": "LOW", "finding": "TLS 1.1 offered"},
            ],
            "errors": [],
        }


class FfufWrapper(ToolWrapper):
    tool_key = "ffuf"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        wordlist = context.get("wordlist", "/usr/share/wordlists/common.txt")
        url = target.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-o", "-", "-s"]

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "ffuf",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["backup_archive_files_found"],
            "findings": [
                {"input": "backup.zip", "status": 200, "length": 4521,
                 "url": target.rstrip("/") + "/backup.zip"}
            ],
            "errors": [],
        }


class WfuzzWrapper(ToolWrapper):
    tool_key = "wfuzz"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        wordlist = context.get("wordlist", "/usr/share/wordlists/common.txt")
        url = target.rstrip("/") + "/FUZZ"
        return ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404", "-f", "-,json", url]

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "wfuzz",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }


class KxssWrapper(ToolWrapper):
    tool_key = "kxss"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        # kxss reads candidate URLs from stdin; this wrapper feeds the single target
        return ["sh", "-c", f"echo {shlex.quote(target)} | kxss"]

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "kxss",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }


class CorsyWrapper(ToolWrapper):
    """Corsy's -o flag writes JSON to a real file path — it has no stdout/'-'
    streaming mode (confirmed against real corsy.py source: `json.dump(results,
    file, ...)`). So this wrapper writes to a temp file and reads it back
    rather than trying to capture JSON from stdout.
    """

    tool_key = "corsy"
    family_id = "F4"
    _last_outfile: str = ""

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json", prefix="corsy_")
        os.close(fd)
        os.remove(path)  # corsy must create it fresh
        self._last_outfile = path
        return ["python3", "corsy.py", "-u", target, "-o", path, "-q"]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = {
            "tool_name": "corsy",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }
        try:
            with open(self._last_outfile) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            result["errors"].append(f"corsy output file unreadable: {exc}")
            return result
        finally:
            if os.path.exists(self._last_outfile):
                os.remove(self._last_outfile)

        for entry in data if isinstance(data, list) else []:
            misconfigs = entry.get("misconfigurations") or []
            if misconfigs:
                result["findings"].append({"url": entry.get("url"), "misconfigurations": misconfigs})
                if any("reflect" in m.lower() or "trust" in m.lower() for m in misconfigs):
                    result["signal_candidates"].append("cors_wildcard_with_credentials")
        result["signal_candidates"] = sorted(set(result["signal_candidates"]))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "corsy",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }


class NiktoWrapper(ToolWrapper):
    """nikto has NO native JSON output (only csv/htm/msf/nbe/txt/xml — confirmed
    against real nikto v2.1.5 -Help). XML output additionally tries to fetch a
    DTD over the network at scan time, which fails in restricted-egress
    environments. The reliable approach is to let nikto print its default
    plain-text stdout and parse the `+ <finding>` lines, which is what this
    wrapper does. -maxtime bounds the scan so it can't hang past our subprocess
    timeout (nikto's own internal timeout fires first and prints a clean
    'maximum execution time reached' line rather than an ugly kill).
    """

    tool_key = "nikto"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        maxtime = context.get("nikto_maxtime", "100s")
        return ["nikto", "-h", target, "-maxtime", str(maxtime), "-nointeractive"]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        signal_candidates: set[str] = set()
        errors: list[str] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            text = line[1:].strip()
            if text.startswith("ERROR:"):
                errors.append(text)
                continue
            if text.startswith(("Target IP:", "Target Hostname:", "Target Port:",
                                 "Start Time:", "End Time:", "Server:")) and "leak" not in text.lower():
                continue  # banner/metadata lines, not findings
            if text.endswith(("host(s) tested",)) or text.startswith("Scan terminated"):
                continue

            findings.append({"finding": text})

            low = text.lower()
            if "x-frame-options" in low or "clickjacking" in low:
                signal_candidates.add("missing_security_headers")
            if "etag" in low or "inode" in low:
                signal_candidates.add("verbose_server_error")
            if low.startswith("cgi") or ("cgi directories" in low and not low.startswith("no ")):
                signal_candidates.add("admin_route_exposed")

        return {
            "tool_name": "nikto",
            "family_id": "F4",
            "target": target,
            "signal_candidates": sorted(signal_candidates),
            "findings": findings,
            "errors": sorted(set(errors)),
        }

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "nikto",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["missing_security_headers"],
            "findings": [
                {"finding": "The anti-clickjacking X-Frame-Options header is not present."},
            ],
            "errors": [],
        }


class WpscanFullWrapper(ToolWrapper):
    tool_key = "wpscan_full"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        return ["wpscan", "--url", target, "--enumerate", "vp,vt,u,cb,dbe",
                "--format", "json", "--no-banner"]

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "wpscan_full",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }


class DroopescanWrapper(ToolWrapper):
    """Real output schema (confirmed by reading dscan/common/output.py and
    dscan/plugins/internal/base_plugin_internal.py source directly, since this
    sandbox has no live Drupal target to test against):

        JsonOutput.result() only prints `json.dumps(result)` if
        `result_anything_found(result)` is True — so EMPTY STDOUT on a
        non-CMS or clean target is correct, expected behavior, not a tool
        failure. Don't treat it as an error.

        When something IS found, the dict is keyed by enumeration category
        ('version', 'plugins', 'themes', 'interesting urls'), each value
        shaped {'finds': [...], 'is_empty': bool}. 'finds' contents vary by
        category (version candidates are strings; plugins/themes are
        typically dicts with name/version).

    Also note: droopescan (and its dependency `cement` 2.x) is unmaintained
    and imports the `imp` module, removed in Python 3.12. It will not even
    start without either a Python <=3.9 environment for that tool, or a
    minimal `imp` shim module providing reload/find_module/load_module via
    importlib (that's what let this wrapper get verified at all).
    """

    tool_key = "droopescan"
    family_id = "F4"

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        cms = context.get("cms", "drupal")  # drupal | wordpress | joomla | silverstripe | moodle
        enumerate_flag = context.get("droopescan_enumerate", "v")  # v=version, a=all, p=plugins, t=themes
        return ["droopescan", "scan", cms, "-u", target, "--output", "json",
                "-e", enumerate_flag, "--hide-progressbar"]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = {
            "tool_name": "droopescan",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }
        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            # Correct, documented behavior: nothing found / not a matching CMS.
            return result

        try:
            data = json.loads(raw_stdout.splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as exc:
            result["errors"].append(f"droopescan output not parseable JSON: {exc}")
            return result

        for category, payload in data.items():
            if category in ("host", "cms_name") or not isinstance(payload, dict):
                continue
            finds = payload.get("finds") or []
            if finds:
                result["findings"].append({"category": category, "finds": finds})
                if category == "version":
                    result["signal_candidates"].append("outdated_server_cms_version")
                elif category in ("plugins", "themes"):
                    result["signal_candidates"].append("vulnerable_plugin_detected")

        result["signal_candidates"] = sorted(set(result["signal_candidates"]))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "droopescan",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }


# ---------------------------------------------------------------------------
# Registry + allowlist
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, type[ToolWrapper]] = {
    "httpx": HttpxWrapper,
    "nuclei_active": NucleiActiveWrapper,
    "testssl_deep": TestsslDeepWrapper,
    "ffuf": FfufWrapper,
    "wfuzz": WfuzzWrapper,
    "kxss": KxssWrapper,
    "corsy": CorsyWrapper,
    "nikto": NiktoWrapper,
    "wpscan_full": WpscanFullWrapper,
    "droopescan": DroopescanWrapper,
}

# Team 4 — Prober allowlist (assignment Section 4)
PROBER_ALLOWLIST: list[str] = [
    "httpx",
    "nuclei_active",
    "testssl_deep",
    "ffuf",
    "wfuzz",
    "kxss",
    "corsy",
    "nikto",
    "wpscan_full",
    "droopescan",
]


def get_tool(tool_key: str) -> ToolWrapper:
    if tool_key not in PROBER_ALLOWLIST:
        raise PermissionError(f"Tool '{tool_key}' is not in the agent-prober allowlist")
    cls = TOOL_REGISTRY[tool_key]
    return cls()
