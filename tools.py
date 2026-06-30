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

    def _empty_result(self, target: str) -> dict[str, Any]:
        """Canonical baseline schema every wrapper must return, even on total failure."""
        return {
            "tool_name": self.tool_key,
            "family_id": self.family_id,
            "target": target,
            "signal_candidates": [],
            "findings": [],
            "errors": [],
        }

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        """Default passthrough parser — subclasses override for structured parsing."""
        result = self._empty_result(target)
        result["raw_stdout"] = raw_stdout[-4000:]  # keep responses bounded
        result["raw_stderr"] = raw_stderr[-1000:] if raw_stderr else ""
        return result

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
            try:
                result = self.parse_output(proc.stdout, proc.stderr, target)
            except Exception as exc:  # parse_output must never crash the agent
                result = self._empty_result(target)
                result["errors"].append(f"{self.tool_key} parser raised {type(exc).__name__}: {exc}")
            result["mock"] = False
            result["return_code"] = proc.returncode
            return result
        except subprocess.TimeoutExpired:
            result = self._empty_result(target)
            result["errors"] = [f"{self.tool_key} timed out after {TOOL_TIMEOUT_SECONDS}s"]
            result["mock"] = False
            return result
        except FileNotFoundError:
            result = self.mock_output(target, context)
            result["mock"] = True
            result["errors"] = [f"{binary} not found on PATH; returned mock output"]
            return result


def _dedupe(items: list[str]) -> list[str]:
    """Stable de-duplication, sorted for deterministic API responses."""
    return sorted(set(s for s in items if s))


# ---------------------------------------------------------------------------
# F1 shared tool
# ---------------------------------------------------------------------------

class HttpxWrapper(ToolWrapper):
    """WARNING — binary name collision risk: the Python `httpx` pip package
    installs its own CLI shim at the same `httpx` name on PATH (it's an HTTP
    client library, not ProjectDiscovery's recon tool). That shim exits 0 even
    when it can't actually run, so a naive return-code check would silently
    treat garbage as a successful scan. This wrapper validates that stdout
    actually parses as the real tool's JSON-lines output before trusting it;
    if it can't, it reports an explicit error pointing at the collision
    instead of fabricating recon data. On a real machine, run `httpx -version`
    and check it mentions "projectdiscovery" before trusting
    `shutil.which('httpx')`.
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
            "signal_candidates": [],
            "findings": [],
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

        # NOTE: main.py's aggregation loop only reads 'findings' and
        # 'signal_candidates' from each tool's result dict — without this,
        # httpx's live/status/title/tech data is computed correctly but
        # silently dropped from the final API response. This exact bug
        # regressed once already; if you touch this wrapper again, keep
        # 'findings' populated.
        result["findings"].append({
            "live": result["live"],
            "status_code": result["status_code"],
            "title": result["title"],
            "tech": result["tech"],
        })
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
            "signal_candidates": [],
            "findings": [{"live": True, "status_code": 200, "title": "Mock Target", "tech": ["nginx"]}],
            "errors": [],
        }


# ---------------------------------------------------------------------------
# F4 (safe) tools — Team 4 Prober allowlist
# ---------------------------------------------------------------------------

class NucleiActiveWrapper(ToolWrapper):
    """Verified: `nuclei -u <target> -jsonl -silent -t http/vulnerabilities/
    -t http/misconfiguration/` streams real JSON-lines straight to stdout (no
    file redirection needed, unlike corsy/testssl_deep). A real run against
    demo.testfire.net returned 0 matches because the target was unreachable
    on 443 (`Skipped ... unresponsive permanently: cause="i/o timeout"`) —
    that's a target-availability issue, not a wrapper bug.

    Real nuclei JSONL lines look like:
    {"template-id": "...", "template-path": "...", "info": {"name": "...",
     "severity": "...", "tags": "..."}, "type": "...", "host": "...",
     "matched-at": "...", "matcher-name": "...", "extracted-results": [...],
     "curl-command": "...", "timestamp": "..."}

    Every field is read defensively with .get() — unknown/missing fields
    never raise, and templates we don't have an explicit signal mapping for
    still parse correctly (they just contribute no signal_candidates beyond
    a severity-based fallback).
    """

    tool_key = "nuclei_active"
    family_id = "F4"

    # keyword -> signal_candidate. Checked against template-id + tags + info.name,
    # all lowercased and joined into one search string per finding.
    _SIGNAL_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
        (("csp", "content-security-policy"), "missing_csp_header"),
        (("hsts", "strict-transport-security"), "missing_hsts_header"),
        (("x-frame-options", "clickjacking"), "missing_x_frame_options_header"),
        (("cors",), "cors_misconfiguration"),
        (("directory-listing", "dir-listing"), "directory_listing_exposed"),
        (("exposed-panel", "admin-panel", "login-panel"), "exposed_admin_panel"),
        ((".git", "git-config", "git-exposure"), "exposed_git"),
        ((".env", "env-exposure", "dotenv"), "exposed_env"),
        (("backup", ".bak", ".zip", ".tar", ".sql"), "exposed_backups"),
        (("sqli", "sql-injection"), "sql_injection_template"),
        (("xss", "cross-site-scripting"), "xss_template"),
        (("rce", "command-injection", "code-execution"), "rce_template"),
        (("ssrf",), "ssrf_template"),
        (("lfi", "rfi", "file-inclusion", "path-traversal"), "lfi_rfi_template"),
    ]

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        return ["nuclei", "-u", target, "-jsonl", "-silent",
                "-t", "http/vulnerabilities/", "-t", "http/misconfiguration/"]

    def _signals_for_entry(self, template_id: str, tags: str, name: str, severity: str) -> set[str]:
        haystack = " ".join([template_id, tags, name]).lower()
        signals: set[str] = set()
        for keywords, signal in self._SIGNAL_KEYWORDS:
            if any(kw in haystack for kw in keywords):
                signals.add(signal)
        if severity in ("medium", "high", "critical"):
            signals.add("confirmed_active_vulnerability")
        return signals

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = self._empty_result(target)
        if not (raw_stdout or "").strip():
            return result  # no matches is a valid, common outcome — not an error

        signal_candidates: set[str] = set()

        for line in raw_stdout.strip().splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                result["errors"].append("skipped one unparseable nuclei JSONL line")
                continue
            if not isinstance(entry, dict):
                continue

            info = entry.get("info") or {}
            if not isinstance(info, dict):
                info = {}

            template_id = entry.get("template-id") or ""
            template_path = entry.get("template-path") or entry.get("template") or ""
            name = info.get("name") or ""
            severity = (info.get("severity") or "").lower()
            tags = info.get("tags") or ""
            if isinstance(tags, list):
                tags = ",".join(str(t) for t in tags)

            finding = {
                "template_id": template_id,
                "template_path": template_path,
                "template_name": name,
                "severity": severity,
                "matched_at": entry.get("matched-at") or target,
                "host": entry.get("host") or "",
                "type": entry.get("type") or "",
                "matcher_name": entry.get("matcher-name") or "",
                "extracted_results": entry.get("extracted-results") or [],
                "curl_command": entry.get("curl-command") or "",
                "timestamp": entry.get("timestamp") or "",
            }
            result["findings"].append(finding)
            signal_candidates |= self._signals_for_entry(template_id, tags, name, severity)

        result["signal_candidates"] = _dedupe(list(signal_candidates))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "nuclei_active",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["missing_csp_header", "missing_hsts_header", "exposed_git"],
            "findings": [
                {
                    "template_id": "missing-csp-header",
                    "template_path": "http/misconfiguration/missing-csp-header.yaml",
                    "template_name": "Missing CSP Header",
                    "severity": "info",
                    "matched_at": target,
                    "host": target,
                    "type": "http",
                    "matcher_name": "csp_header",
                    "extracted_results": [],
                    "curl_command": f"curl -X GET {target}",
                    "timestamp": "2026-06-30T13:55:00+05:30",
                },
                {
                    "template_id": "git-config",
                    "template_path": "http/exposures/configs/git-config.yaml",
                    "template_name": "Git Config File",
                    "severity": "medium",
                    "matched_at": target.rstrip("/") + "/.git/config",
                    "host": target,
                    "type": "http",
                    "matcher_name": "git_config_word",
                    "extracted_results": ["[core]"],
                    "curl_command": f"curl -X GET {target.rstrip('/')}/.git/config",
                    "timestamp": "2026-06-30T13:55:05+05:30",
                },
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
    """Verified on Kali: `-o -` does NOT write JSON to stdout on this ffuf
    version — it only prints the bare discovered-path list, identical to
    running without -o at all (confirmed: `head -40 ffuf_output.json` after
    using `-o -` showed only plain path names, no JSON). Same file-vs-stdout
    mistake as corsy/testssl_deep. Fixed: write JSON to a real temp file via
    `-o <path>` and read it back in parse_output(), same pattern as corsy.

    Findings filter: ffuf's results include every status in the default
    matcher set (200-299,301,302,307,401,403,405,500), which includes a lot
    of noise — zero-length 200s for Windows-reserved names (con/aux/nul/
    lpt1/lpt2/com1-3) that IIS-style stacks 200 on without content. Those are
    dropped. Redirects (301/302/307) ARE kept even at zero body length,
    because a redirect to a login page (e.g. /admin, /bank -> /login.jsp)
    reveals a real gated route exists — that's a genuine finding, not noise.
    """

    tool_key = "ffuf"
    family_id = "F4"
    _last_outfile: str = ""

    # extension/keyword -> signal_candidate, checked against the fuzz input lowercased.
    _EXTENSION_SIGNALS: list[tuple[tuple[str, ...], str]] = [
        ((".git",), "exposed_git"),
        ((".env",), "exposed_env"),
        ((".sql", ".db", ".sqlite", ".dump"), "exposed_database_dump"),
        ((".bak", ".backup", ".old", ".zip", ".tar", ".tar.gz", ".7z"), "backup_file"),
        ((".conf", ".config", ".ini", ".yml", ".yaml", ".cfg"), "configuration_file"),
        ((".pem", ".key", ".crt", ".log", ".pfx"), "sensitive_file"),
    ]
    _KEYWORD_SIGNALS: list[tuple[tuple[str, ...], str]] = [
        (("admin", "panel", "wp-admin", "administrator", "manage"), "exposed_admin_panel"),
        (("login", "signin", "auth"), "login_endpoint"),
        (("api", "rest", "graphql"), "api_endpoint"),
    ]

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
        os.close(fd)
        os.remove(path)  # ffuf must create it fresh
        self._last_outfile = path

        wordlist = context.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        url = target.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", url, "-w", wordlist, "-of", "json",
                "-o", path, "-s"]

    def _signals_for_entry(self, fuzz_input: str, status: int, is_redirect: bool,
                            redirect: str, content_type: str) -> set[str]:
        low = (fuzz_input or "").lower()
        signals: set[str] = set()

        for exts, signal in self._EXTENSION_SIGNALS:
            if any(low.endswith(ext) for ext in exts):
                signals.add(signal)
        for keywords, signal in self._KEYWORD_SIGNALS:
            if any(kw in low for kw in keywords) and status in (200, 301, 302, 307, 401, 403, 405):
                signals.add(signal)

        if low in ("admin", "bank") and (is_redirect or status in (401, 403)):
            signals.add("admin_route_exposed")  # preserved from earlier version

        if any(low.endswith(ext) for ext in (".bak", ".zip", ".tar", ".sql", ".old")):
            signals.add("backup_archive_files_found")  # preserved from earlier version

        # a redirect to a path ending in "/" with the same name (e.g. images -> /images/,
        # static -> /static/) is a real directory, not just a gated route.
        if is_redirect and redirect.rstrip().endswith("/"):
            signals.add("exposed_directory")

        return signals

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = self._empty_result(target)
        try:
            with open(self._last_outfile) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            result["errors"].append(f"ffuf output file unreadable: {exc}")
            return result
        finally:
            if os.path.exists(self._last_outfile):
                os.remove(self._last_outfile)

        if not isinstance(data, dict):
            result["errors"].append("ffuf output file did not contain a JSON object")
            return result

        signal_candidates: set[str] = set()
        results = data.get("results") or []
        if not isinstance(results, list):
            result["errors"].append("ffuf 'results' field was not a list")
            return result

        for entry in results:
            if not isinstance(entry, dict):
                continue
            status = entry.get("status")
            url = entry.get("url") or target
            length = entry.get("length") or 0
            redirect = entry.get("redirectlocation") or ""
            input_block = entry.get("input") or {}
            fuzz_input = input_block.get("FUZZ", "") if isinstance(input_block, dict) else ""
            content_type = entry.get("content-type") or ""

            is_redirect = status in (301, 302, 307) and bool(redirect)
            is_real_page = status in (200, 401, 403, 405) and length > 0
            if not (is_redirect or is_real_page):
                continue  # drop zero-length, non-redirect noise (e.g. con/aux/nul)

            result["findings"].append({
                "input": fuzz_input,
                "status": status,
                "url": url,
                "length": length,
                "words": entry.get("words"),
                "lines": entry.get("lines"),
                "content_type": content_type,
                "duration_ns": entry.get("duration"),
                "redirect_location": redirect or None,
                "host": entry.get("host") or "",
            })

            signal_candidates |= self._signals_for_entry(fuzz_input, status, is_redirect,
                                                           redirect, content_type)

        result["signal_candidates"] = _dedupe(list(signal_candidates))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        base = target.rstrip("/")
        return {
            "tool_name": "ffuf",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [
                "backup_archive_files_found", "backup_file", "admin_route_exposed",
                "exposed_admin_panel", "exposed_directory", "configuration_file",
            ],
            "findings": [
                {
                    "input": "backup.zip", "status": 200, "url": base + "/backup.zip",
                    "length": 4521, "words": 12, "lines": 3, "content_type": "application/zip",
                    "duration_ns": 256000000, "redirect_location": None, "host": target,
                },
                {
                    "input": "admin", "status": 302, "url": base + "/admin",
                    "length": 0, "words": 1, "lines": 1, "content_type": "",
                    "duration_ns": 254000000, "redirect_location": "/login.jsp", "host": target,
                },
                {
                    "input": "static", "status": 302, "url": base + "/static",
                    "length": 0, "words": 1, "lines": 1, "content_type": "",
                    "duration_ns": 268000000, "redirect_location": "/static/", "host": target,
                },
                {
                    "input": "config.yml", "status": 200, "url": base + "/config.yml",
                    "length": 312, "words": 8, "lines": 14, "content_type": "text/yaml",
                    "duration_ns": 251000000, "redirect_location": None, "host": target,
                },
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
    """Verified: piping a single URL into `kxss` works as designed. Two real
    runs against demo.testfire.net (`/` and `/search.aspx?q=test`) produced
    no output — that's correct kxss behavior, it only prints a block when it
    finds an unfiltered reflection of its probe characters, and neither URL
    reflected anything unfiltered. Real kxss output (when it does find a
    reflection) is line-oriented blocks:

        URL: https://target/search.aspx?q=test
        Param: q
        Unfiltered: " ' < >

    repeated per finding. The parser below is a small state machine rather
    than a strict block-by-block split, so it tolerates blank lines inside
    or between blocks, extra leading/trailing whitespace, blocks missing a
    field, and unrecognized future lines (e.g. a hypothetical "Severity:"
    field) without breaking. Empty stdout is treated as "nothing found,"
    not an error.
    """

    tool_key = "kxss"
    family_id = "F4"

    _KNOWN_PREFIXES = ("URL:", "Param:", "Unfiltered:", "Severity:")

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        # kxss reads candidate URLs from stdin; this wrapper feeds the single target
        return ["sh", "-c", f"echo {shlex.quote(target)} | kxss"]

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = self._empty_result(target)
        if not (raw_stdout or "").strip():
            return result  # no reflection found — expected, not an error

        current: dict[str, Any] = {}

        def flush():
            if current.get("url") and current.get("param"):
                result["findings"].append({
                    "url": current.get("url"),
                    "param": current.get("param"),
                    "unfiltered_chars": current.get("unfiltered_chars", ""),
                    "severity": current.get("severity"),  # None unless a future kxss version emits it
                })
                result["signal_candidates"].append("reflected_xss_candidate")

        for raw_line in raw_stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue  # tolerate blank lines anywhere

            matched_prefix = next((p for p in self._KNOWN_PREFIXES if line.startswith(p)), None)
            if matched_prefix is None:
                continue  # ignore unrecognized lines instead of failing

            value = line[len(matched_prefix):].strip()
            if matched_prefix == "URL:":
                flush()  # a new URL line starts a new block — flush the previous one
                current = {"url": value}
            elif matched_prefix == "Param:":
                current["param"] = value
            elif matched_prefix == "Unfiltered:":
                current["unfiltered_chars"] = value
            elif matched_prefix == "Severity:":
                current["severity"] = value

        flush()  # flush the final block

        result["signal_candidates"] = _dedupe(result["signal_candidates"])
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": "kxss",
            "family_id": "F4",
            "target": target,
            "signal_candidates": ["reflected_xss_candidate"],
            "findings": [
                {"url": target + "?q=test", "param": "q",
                 "unfiltered_chars": "\" ' < >", "severity": None}
            ],
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
    """Verified: `--format json --no-banner` does stream valid JSON to stdout
    on real runs (confirmed twice against demo.testfire.net: one SSL
    handshake-failure case, one not-WordPress case — both produced
    well-formed JSON). `scan_aborted` is a normal wpscan outcome (target
    down, or simply not WordPress), not a wrapper failure, so it's surfaced
    as an info finding rather than an error.

    Every section below is read defensively: a missing 'plugins', 'themes',
    'users', 'version', or 'interesting_findings' key (e.g. because that
    --enumerate flag wasn't actually run) just means that finding type is
    skipped, not an error.
    """

    tool_key = "wpscan_full"
    family_id = "F4"

    _INTERESTING_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
        (("config", "backup"), "config_backup_exposed"),
        (("debug", "debug.log"), "debug_log_exposed"),
        (("directory listing", "dir listing"), "directory_listing_exposed"),
        (("xmlrpc", "xml-rpc"), "xmlrpc_exposed"),
        (("readme",), "readme_exposed"),
    ]

    def build_command(self, target: str, context: dict[str, Any]) -> list[str]:
        return ["wpscan", "--url", target, "--enumerate", "vp,vt,u,cb,dbe",
                "--format", "json", "--no-banner"]

    def _vuln_summary(self, vuln: dict[str, Any]) -> dict[str, Any]:
        references = vuln.get("references") or {}
        if not isinstance(references, dict):
            references = {}
        return {
            "title": vuln.get("title"),
            "fixed_in": vuln.get("fixed_in"),
            "references": {
                "url": references.get("url") or [],
                "cve": references.get("cve") or [],
            },
        }

    def parse_output(self, raw_stdout: str, raw_stderr: str, target: str) -> dict[str, Any]:
        result = self._empty_result(target)

        raw_stdout = (raw_stdout or "").strip()
        if not raw_stdout:
            result["errors"].append("wpscan produced no stdout")
            return result

        try:
            data = json.loads(raw_stdout)
        except json.JSONDecodeError as exc:
            result["errors"].append(f"wpscan output not parseable JSON (possibly truncated): {exc}")
            return result
        if not isinstance(data, dict):
            result["errors"].append("wpscan output was not a JSON object")
            return result

        # scan_aborted is a normal wpscan outcome (target down, or not WordPress
        # at all) — not a wrapper failure. Surface it as info, not an error.
        scan_aborted = data.get("scan_aborted")
        if scan_aborted:
            result["findings"].append({"type": "scan_aborted", "reason": scan_aborted})
            return result

        signal_candidates: set[str] = set()

        # --- core version ---
        core = data.get("version")
        if isinstance(core, dict) and (core.get("number") or core.get("vulnerabilities")):
            core_finding = {
                "type": "core_version",
                "number": core.get("number"),
                "release_date": core.get("release_date"),
                "vulnerabilities": [self._vuln_summary(v) for v in (core.get("vulnerabilities") or [])
                                     if isinstance(v, dict)],
            }
            result["findings"].append(core_finding)
            if core_finding["vulnerabilities"]:
                signal_candidates.add("outdated_server_cms_version")

        # --- plugins ---
        plugins = data.get("plugins")
        if isinstance(plugins, dict):
            for plugin_name, plugin in plugins.items():
                if not isinstance(plugin, dict):
                    continue
                plugin_version = plugin.get("version") or {}
                if not isinstance(plugin_version, dict):
                    plugin_version = {}
                vulns = [self._vuln_summary(v) for v in (plugin.get("vulnerabilities") or [])
                         if isinstance(v, dict)]
                if not (vulns or plugin_version.get("number") or plugin.get("location")):
                    continue
                result["findings"].append({
                    "type": "plugin",
                    "name": plugin_name,
                    "version": plugin_version.get("number"),
                    "location": plugin.get("location"),
                    "vulnerabilities": vulns,
                })
                if vulns:
                    signal_candidates.add("vulnerable_plugin_detected")

        # --- themes ---
        themes = data.get("themes")
        if isinstance(themes, dict):
            for theme_name, theme in themes.items():
                if not isinstance(theme, dict):
                    continue
                theme_version = theme.get("version") or {}
                if not isinstance(theme_version, dict):
                    theme_version = {}
                vulns = [self._vuln_summary(v) for v in (theme.get("vulnerabilities") or [])
                         if isinstance(v, dict)]
                if not (vulns or theme_version.get("number")):
                    continue
                result["findings"].append({
                    "type": "theme",
                    "name": theme_name,
                    "version": theme_version.get("number"),
                    "vulnerabilities": vulns,
                })
                if vulns:
                    signal_candidates.add("vulnerable_theme_detected")

        # --- users (only present if -e u enumeration ran and found accounts) ---
        users = data.get("users")
        if isinstance(users, dict) and users:
            usernames = sorted(u for u in users.keys() if u)
            if usernames:
                result["findings"].append({"type": "users", "usernames": usernames})
                signal_candidates.add("usernames_enumerated")

        # --- interesting findings (config backups, debug logs, xmlrpc, readme, dir listing) ---
        interesting = data.get("interesting_findings")
        if isinstance(interesting, list):
            for item in interesting:
                if not isinstance(item, dict):
                    continue
                item_type = (item.get("type") or "").lower()
                description = item.get("to_s") or item.get("url") or ""
                haystack = f"{item_type} {description}".lower()
                matched_signal = None
                for keywords, signal in self._INTERESTING_KEYWORDS:
                    if any(kw in haystack for kw in keywords):
                        matched_signal = signal
                        break
                result["findings"].append({
                    "type": "interesting_finding",
                    "subtype": item_type or None,
                    "url": item.get("url"),
                    "description": description or None,
                    "references": item.get("references") or {},
                })
                if matched_signal:
                    signal_candidates.add(matched_signal)

        result["signal_candidates"] = _dedupe(list(signal_candidates))
        return result

    def mock_output(self, target: str, context: dict[str, Any]) -> dict[str, Any]:
        base = target.rstrip("/")
        return {
            "tool_name": "wpscan_full",
            "family_id": "F4",
            "target": target,
            "signal_candidates": [
                "outdated_server_cms_version", "vulnerable_plugin_detected",
                "config_backup_exposed", "xmlrpc_exposed",
            ],
            "findings": [
                {
                    "type": "core_version", "number": "5.8", "release_date": "2021-07-20",
                    "vulnerabilities": [
                        {"title": "WordPress < 5.8.1 - Object Injection", "fixed_in": "5.8.1",
                         "references": {"url": ["https://wpscan.com/vulnerability/mock"], "cve": ["CVE-2021-MOCK"]}},
                    ],
                },
                {
                    "type": "plugin", "name": "akismet", "version": "4.1.0",
                    "location": base + "/wp-content/plugins/akismet/",
                    "vulnerabilities": [
                        {"title": "Akismet < 4.1.3 - Mock Stored XSS", "fixed_in": "4.1.3",
                         "references": {"url": ["https://wpscan.com/vulnerability/mock2"], "cve": []}},
                    ],
                },
                {
                    "type": "interesting_finding", "subtype": "config_backup",
                    "url": base + "/wp-config.php.bak",
                    "description": "Config backup found", "references": {},
                },
                {
                    "type": "interesting_finding", "subtype": "xmlrpc",
                    "url": base + "/xmlrpc.php",
                    "description": "XML-RPC seems to be enabled", "references": {},
                },
            ],
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
