"""main.py

agent-prober — Team 4 ReconAgent specialist (F4 Active Scan, safe tier).

Run:
    uvicorn main:app --port 8004 --reload

Env vars:
    TOOL_MOCK_MODE=true|false   (default: true — no real scanning binaries needed)
    TOOL_TIMEOUT_SECONDS=120    (per-tool subprocess timeout)
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, HTTPException

from models import HealthResponse, TaskRequest, TaskResponse, TaskResponseBody
from planner import select_tools
from tools import MOCK_MODE, PROBER_ALLOWLIST, get_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-prober")

AGENT_ID = "agent-prober"

app = FastAPI(title="ReconAgent — agent-prober", version="1.0.0")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        agent_id=AGENT_ID,
        status="ok",
        mock_mode=MOCK_MODE,
        tool_allowlist=PROBER_ALLOWLIST,
    )


@app.post("/agents/{agent_id}/tasks", response_model=TaskResponse)
def run_task(agent_id: str, request: TaskRequest) -> TaskResponse:
    if agent_id != AGENT_ID:
        raise HTTPException(status_code=404, detail=f"Unknown agent_id '{agent_id}', expected '{AGENT_ID}'")

    if not request.target:
        return TaskResponse(
            agent_id=AGENT_ID,
            status="failed",
            response={},
            error="target is required",
        )

    try:
        tool_keys = select_tools(request.prompt, request.context)
        logger.info("agent-prober selected tools=%s for target=%s", tool_keys, request.target)

        findings: list[dict] = []
        signal_candidates: set[str] = set()
        tool_errors: list[str] = []

        for tool_key in tool_keys:
            tool = get_tool(tool_key)
            result = tool.run(request.target, request.context)

            for f in result.get("findings", []):
                f_with_source = dict(f)
                f_with_source["source_tool"] = tool_key
                findings.append(f_with_source)

            signal_candidates.update(result.get("signal_candidates", []))
            tool_errors.extend(result.get("errors", []))

        summary = (
            f"Ran {len(tool_keys)} tool(s) ({', '.join(tool_keys)}) against {request.target}. "
            f"{len(findings)} finding(s), {len(signal_candidates)} distinct signal(s)."
        )
        if tool_errors:
            summary += f" {len(tool_errors)} tool-level warning(s) — see findings for detail."

        return TaskResponse(
            agent_id=AGENT_ID,
            status="completed",
            response=TaskResponseBody(
                summary=summary,
                findings=[
                    {
                        "signal_candidates": sorted(signal_candidates),
                        "tools_used": tool_keys,
                        "tool_errors": tool_errors,
                        "details": findings,
                    }
                ],
            ),
        )

    except PermissionError as exc:
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={}, error=str(exc))
    except Exception as exc:  # noqa: BLE001 — top-level safety net per Section 3 contract
        logger.exception("agent-prober task failed")
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={}, error=str(exc))


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8004"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
