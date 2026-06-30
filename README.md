# agent-prober (Team 4)

F4 Active Scan (safe tier) specialist agent. Port 8004, agent_id `agent-prober`.

## Setup

```bash
pip install fastapi uvicorn pydantic httpx
export TOOL_MOCK_MODE=true   # set to false once binaries are installed + target is approved
uvicorn main:app --port 8004 --reload
```

## Env vars

| Var | Default | Purpose |
|---|---|---|
| `TOOL_MOCK_MODE` | `true` | When true (or a binary is missing), tools return canned mock output instead of shelling out. |
| `TOOL_TIMEOUT_SECONDS` | `120` | Per-tool subprocess timeout. |
| `PORT` | `8004` | Used only when running `python3 main.py` directly. |

## Endpoints

`GET /health` → agent status + tool allowlist.

`POST /agents/agent-prober/tasks` → prompt in, structured response out.

## curl example

```bash
curl -X POST "http://localhost:8004/agents/agent-prober/tasks" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Run active scans on https://target.example.com using upstream context. Check TLS and CORS.","target":"https://target.example.com","context":{}}'
```

## How tool selection works

`planner.py` is a transparent keyword-rule selector: it always runs `httpx`
(live check) and `nuclei_active` (general active-scan default), then adds
tools when the prompt mentions related keywords (e.g. "tls"/"ssl" →
`testssl_deep`, "cors" → `corsy`, "wordpress" → `wpscan_full`). If upstream
`context` flags `injectable_params_found`, `ffuf` is added automatically.

## Allowlist enforcement

`tools.py::get_tool()` raises `PermissionError` for any tool key not in
`PROBER_ALLOWLIST`. The FastAPI handler catches this and returns
`status: "failed"` with the error message rather than crashing.

## Real-tool verification log

Tested in a sandbox with restricted network egress (couldn't reach actual lab
targets like testfire.net, only allowlisted domains like pypi.org — used purely
to capture real output shapes, not as a security test).

**Verified against real tool output, bugs found and fixed:**

- `nikto` — does NOT support JSON output (only csv/htm/msf/nbe/xml/txt). XML mode
  additionally tries to fetch a DTD over the network and fails in restricted
  environments. Fixed: wrapper now uses default stdout text output and parses
  `+ <finding>` lines, with `-maxtime` to bound scan length.
- `corsy` — its `-o` flag writes to a real file path, there's no stdout/`-`
  streaming mode. Fixed: wrapper writes to a temp file and reads it back.
- `httpx` — **binary name collision risk**: the Python `httpx` pip package
  installs its own same-named CLI shim, which is a completely different tool
  (HTTP client library, not ProjectDiscovery's recon scanner). It exits 0 even
  when it can't run, so a naive return-code check would silently treat garbage
  as a successful scan. Fixed: wrapper now validates stdout actually parses as
  real JSON-lines output and reports an explicit collision warning if not.
  **Before running for real, run `httpx -version` yourself and confirm it
  mentions ProjectDiscovery, not the Python package.**
- `testssl_deep` — same file-vs-stdout mistake as corsy: `--jsonfile-pretty -`
  is NOT a stdout convention, "-" is treated as a literal filename and errors
  if it already exists. Fixed: wrapper writes to a real temp file. Verified
  real schema by running a live scan: top-level `scanResult` is a list; the
  per-target entry (the one with a `targetHost` key) has nested category
  lists (`protocols`, `ciphers`, `vulnerabilities`, etc.), each a list of
  `{id, severity, finding}` dicts. Parser now reads `protocols` (weak TLS
  versions) and `vulnerabilities` directly from real-confirmed paths.
- `droopescan` — same `imp` module problem as wfuzz (see below), plus once
  patched, confirmed by reading its actual source
  (`dscan/common/output.py`): the JSON result is **only printed to stdout when
  something is found** (`result_anything_found(result)` gate) — empty stdout
  on a clean/non-CMS target is correct droopescan behavior, not a tool
  failure. The wrapper previously had no schema basis at all; now it's based
  directly on `base_plugin_internal.py`'s real result-building code: top-level
  dict keyed by enumeration category (`version`, `plugins`, `themes`,
  `interesting urls`), each `{'finds': [...], 'is_empty': bool}`.
- `wfuzz` and `droopescan` (PyPI versions) — both broken on Python 3.10+:
  `wfuzz` imports the removed `imp` module via an old dependency chain;
  `droopescan`'s pinned `cement` 2.6.2 dependency does the same, and
  `droopescan` itself isn't compatible with newer `cement` either (different
  API). If your Python is 3.10+ (yours was 3.14.5 per Day 13 notes), neither
  tool runs out of the box. Workaround used here: a minimal `imp.py` shim
  module backed by `importlib` (reload/find_module/load_module), placed
  alongside `cement` in site-packages — this got `droopescan` running for
  real verification. `wfuzz` itself wasn't patched (lower priority — `ffuf`
  covers the same fuzzing need); same shim approach would likely work for it
  too if you decide you need it.
- Default `TOOL_TIMEOUT_SECONDS` raised from 120 to 300 — real scans
  (corsy, testssl.sh in particular) routinely exceed 120s.

**Not yet tested against real binaries** (Go binaries needing `go install`
unreachable from this sandbox, or `wpscan`'s Ruby gem dependency unreachable):
`nuclei_active`, `ffuf`, `kxss`, `wpscan_full`. Their `mock_output()` shapes
are reasonable guesses, not confirmed real schemas — verify the same way (run
the real binary against an approved lab target, diff the actual JSON against
what `parse_output()` expects) before relying on them for grading.



- Only scan instructor-approved lab targets, or leave `TOOL_MOCK_MODE=true`.
- Never point this at production systems without written approval.
- Mock mode is the default — real subprocess execution requires explicitly
  setting `TOOL_MOCK_MODE=false` AND having the binary on PATH.
