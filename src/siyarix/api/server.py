# SPDX-License-Identifier: AGPL-3.0-or-later
"""Siyarix API Server and WebSocket Streaming."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Security,
    status,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from siyarix.core import AgentCore
from siyarix.core import AgentGoal, AgentMode

logger = logging.getLogger(__name__)

app = FastAPI(title="Siyarix API", version="3.0.0")
security = HTTPBearer()

# Store active sessions and their core instances
_sessions: dict[str, AgentCore] = {}


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """Verify JWT token."""
    api_key = os.getenv("SIYARIX_API_KEY")
    if not api_key:
        # Allow any valid JWT when no key is configured
        return credentials.credentials
    if credentials.credentials != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


class ScanRequest(BaseModel):
    target: str
    mode: str = "offline"


class ChatRequest(BaseModel):
    query: str


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan")
async def start_scan(req: ScanRequest, token: str = Depends(verify_token)) -> dict[str, str]:
    session_id = f"sess_{int(time.time())}"
    mode = AgentMode(req.mode) if req.mode in [m.value for m in AgentMode] else AgentMode.REGISTRY
    core = AgentCore(mode=mode)
    await core.start()
    _sessions[session_id] = core

    async def run_in_bg() -> None:
        try:
            from siyarix.core import AgentGoal

            goal = AgentGoal(description=f"Scan target: {req.target}")
            await core.execute_goal(goal)
        finally:
            await core.shutdown()

    asyncio.create_task(run_in_bg())
    return {"session_id": session_id, "status": "started"}


@app.get("/v1/scan/{session_id}")
async def get_scan(session_id: str, token: str = Depends(verify_token)) -> dict[str, Any]:
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    core = _sessions[session_id]
    return core.stats()


@app.delete("/v1/scan/{session_id}")
async def abort_scan(session_id: str, token: str = Depends(verify_token)) -> dict[str, str]:
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    core = _sessions[session_id]
    await core.shutdown()
    return {"status": "aborted"}


@app.get("/v1/sessions")
async def list_sessions(token: str = Depends(verify_token)) -> dict[str, list[str]]:
    return {"sessions": list(_sessions.keys())}


@app.post("/v1/chat")
async def chat_query(req: ChatRequest, token: str = Depends(verify_token)) -> dict[str, Any]:
    core = AgentCore(mode=AgentMode.AUTONOMOUS)
    await core.start()
    goal = AgentGoal(description=req.query)
    result = await core.execute_goal(goal)
    await core.shutdown()
    return {
        "success": result.success,
        "summary": result.summary,
        "findings": result.findings,
    }


@app.get("/v1/tools")
async def list_tools(token: str = Depends(verify_token)) -> dict[str, list[str]]:
    core = AgentCore()
    await core.start()
    tools = [t.name for t in core.registry.list_tools()]
    return {"tools": tools}


@app.get("/v1/providers")
async def list_providers(token: str = Depends(verify_token)) -> dict[str, Any]:
    core = AgentCore()
    await core.start()
    # Mocked provider list based on env
    return {"providers": {"openai": bool(os.getenv("OPENAI_API_KEY"))}}


@app.get("/v1/graph")
async def export_graph(token: str = Depends(verify_token)) -> dict[str, Any]:
    import json

    core = AgentCore()
    await core.start()
    kg_json = core._knowledge_graph.to_json()
    return json.loads(kg_json)


@app.websocket("/v1/stream/{session_id}")
async def websocket_stream(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    if session_id not in _sessions:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Subscribe to the event bus
    from siyarix.events import get_event_bus

    bus = get_event_bus()
    queue: asyncio.Queue[dict] = asyncio.Queue()

    async def event_handler(event: Any) -> None:
        try:
            # Convert enum or dataclass to dict
            data = {"type": str(event.type), "source": event.source, "data": event.data}
            await queue.put(data)
        except Exception as e:
            logger.error("Error queueing event: %s", e)

    bus.on(None, event_handler)

    try:
        while True:
            event_dict = await queue.get()
            await websocket.send_json(event_dict)
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for session %s", session_id)
    finally:
        pass
