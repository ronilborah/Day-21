"""models.py

Pydantic schemas for the ReconAgent API contract (Section 3 of the assignment).
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class TaskRequest(BaseModel):
    prompt: str = Field(..., description="Natural-language task for the agent.")
    target: str = Field(..., description="URL or hostname in scope.")
    context: dict[str, Any] = Field(default_factory=dict, description="Optional upstream agent context.")


class TaskResponseBody(BaseModel):
    summary: str
    findings: list[dict[str, Any]] = Field(default_factory=list)


class TaskResponse(BaseModel):
    agent_id: str
    status: Literal["completed", "failed"]
    response: TaskResponseBody | dict[str, Any]
    error: str | None = None


class HealthResponse(BaseModel):
    agent_id: str
    status: Literal["ok"]
    mock_mode: bool
    tool_allowlist: list[str]
