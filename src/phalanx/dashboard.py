"""Web Dashboard infrastructure for Siyarix.

Provides a lightweight async HTTP dashboard with live scan progress,
Knowledge Graph visualization, findings heatmap, and system monitoring.
Serves real REST API endpoints and WebSocket/SSE live updates.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# optional dependency gates
# ---------------------------------------------------------------------------
try:
    import websockets
    from websockets.asyncio.server import ServerConnection as WSConnection

    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    refresh_interval: int = 5
    enable_cors: bool = True
    auth_token: str = ""
    max_history: int = 100


@dataclass
class DashboardSnapshot:
    timestamp: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    active_scans: list[dict[str, Any]] = field(default_factory=list)
    recent_findings: list[dict[str, Any]] = field(default_factory=list)
    graph_stats: dict[str, Any] = field(default_factory=dict)
    system_health: dict[str, Any] = field(default_factory=dict)
    agent_status: list[dict[str, Any]] = field(default_factory=list)
    top_tools: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "metrics": self.metrics,
            "active_scans": self.active_scans[:20],
            "recent_findings": self.recent_findings[:50],
            "graph_stats": self.graph_stats,
            "system_health": self.system_health,
            "agent_status": self.agent_status,
            "top_tools": self.top_tools[:10],
        }


class _DashboardHTTPHandler(BaseHTTPRequestHandler):
    """Request handler that dispatches to the parent DashboardService."""

    service: DashboardService | None = None

    # ------------------------------------------------------------------
    # silence per-request stderr logging
    # ------------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("HTTP %s %s", self.command, self.path)

    # ------------------------------------------------------------------
    # dispatch table
    # ------------------------------------------------------------------
    _ROUTES: dict[str, tuple[str, str]] = {
        "/health": ("GET", "_handle_health"),
        "/metrics": ("GET", "_handle_metrics"),
        "/findings": ("GET", "_handle_findings"),
        "/agents": ("GET", "_handle_agents"),
        "/graph": ("GET", "_handle_graph"),
    }

    def _send_json(self, data: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _set_cors_headers(self) -> None:
        cfg = self.service._config if self.service else None
        if cfg and cfg.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers", "Content-Type, Authorization"
            )

    def _check_auth(self) -> bool:
        cfg = self.service._config if self.service else None
        token = cfg and cfg.auth_token
        if not token:
            return True
        return self.headers.get("Authorization", "").removeprefix("Bearer ") == token

    # ------------------------------------------------------------------
    # route handlers
    # ------------------------------------------------------------------
    def _handle_health(self) -> None:
        assert self.service is not None
        self._send_json(self.service._build_health_response())

    def _handle_metrics(self) -> None:
        assert self.service is not None
        self._send_json(self.service._build_metrics_response())

    def _handle_findings(self) -> None:
        assert self.service is not None
        limit = int(self._get_query_param("limit", "50"))
        self._send_json(self.service._build_findings_response(limit))

    def _handle_agents(self) -> None:
        assert self.service is not None
        self._send_json(self.service._build_agent_response())

    def _handle_graph(self) -> None:
        assert self.service is not None
        self._send_json(self.service._build_graph_response())

    # ------------------------------------------------------------------
    # SSE live stream
    # ------------------------------------------------------------------
    def _handle_sse(self) -> None:
        assert self.service is not None
        self.send_response(HTTPStatus.OK)
        self._set_cors_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        interval = self.service._config.refresh_interval
        try:
            while not self.service._stop_sse:
                snapshot = self.service.build_snapshot()
                data = f"data: {json.dumps(snapshot.to_dict(), default=str)}\n\n"
                self.wfile.write(data.encode("utf-8"))
                self.wfile.flush()
                # cooperative sleep via a small event so we can be interrupted
                if self.service._sse_event.wait(timeout=interval):
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    # ------------------------------------------------------------------
    # HTTP method dispatchers
    # ------------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        path = self.path.split("?")[0]

        # SSE live stream
        if path == "/ws/live" and self._get_query_param("stream", "").lower() == "sse":
            self._handle_sse()
            return

        # REST routes
        route = self._ROUTES.get(path)
        if route is None:
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return

        expected_method, handler_name = route
        if self.command != expected_method:
            self._send_json(
                {"error": "method not allowed"}, HTTPStatus.METHOD_NOT_ALLOWED
            )
            return

        handler = getattr(self, handler_name, None)
        if handler is None:
            self._send_json(
                {"error": "internal error"}, HTTPStatus.INTERNAL_SERVER_ERROR
            )
            return
        handler()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _get_query_param(self, name: str, default: str = "") -> str:
        if "?" not in self.path:
            return default
        qs = self.path.split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k == name:
                    return v
        return default


class DashboardService:
    """Async HTTP dashboard service for Siyarix.

    Provides REST API endpoints for:
    - GET /health  — System health status
    - GET /metrics — Current metrics snapshot
    - GET /findings — Recent findings
    - GET /agents  — Agent status
    - GET /graph   — Knowledge graph stats
    - GET /ws/live?stream=sse — SSE live stream
    - WS /ws/live  — WebSocket for live updates (requires ``websockets``)
    """

    def __init__(
        self, engine: Any = None, config: DashboardConfig | None = None
    ) -> None:
        self._engine = engine
        self._config = config or DashboardConfig()
        self._started = False
        self._stop_sse = False
        self._sse_event = threading.Event()
        self._snapshots: list[DashboardSnapshot] = []
        self._http_server: HTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._ws_server: Any = None

    def set_engine(self, engine: Any) -> None:
        self._engine = engine

    def build_snapshot(self) -> DashboardSnapshot:
        snapshot = DashboardSnapshot(timestamp=datetime.now().isoformat())

        if self._engine:
            try:
                kg = getattr(self._engine, "graph", None)
                if kg:
                    snapshot.graph_stats = kg.stats() if hasattr(kg, "stats") else {}
            except Exception:
                pass

            try:
                from .metrics import get_metrics

                m = get_metrics()
                snapshot.metrics = m.to_dict() if hasattr(m, "to_dict") else {}
            except Exception:
                pass

            try:
                tools = getattr(self._engine, "discovered_tools", [])
                snapshot.top_tools = [(t.name, 0) for t in tools[:10]]
            except Exception:
                pass

        self._snapshots.append(snapshot)
        if len(self._snapshots) > self._config.max_history:
            self._snapshots = self._snapshots[-self._config.max_history :]
        return snapshot

    def get_snapshots(self, limit: int = 10) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._snapshots[-limit:]]

    def _build_health_response(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "service": "siyarix-dashboard",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
        }

    def _build_metrics_response(self) -> dict[str, Any]:
        try:
            from .metrics import get_metrics

            return get_metrics().to_dict() if hasattr(get_metrics(), "to_dict") else {}
        except Exception:
            return {}

    def _build_findings_response(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self._engine:
            return []
        kg = getattr(self._engine, "graph", None)
        if not kg:
            return []
        nodes: list = getattr(kg, "find_nodes", lambda: [])()
        return [n.to_dict() for n in nodes[:limit]]

    def _build_agent_response(self) -> list[dict[str, Any]]:
        if not self._engine:
            return []
        team = getattr(self._engine, "_team", None)
        if not team:
            return []
        return getattr(team, "list_agents", lambda: [])()

    def _build_graph_response(self) -> dict[str, Any]:
        if not self._engine:
            return {}
        kg = getattr(self._engine, "graph", None)
        if not kg:
            return {}
        stats: dict = getattr(kg, "stats", lambda: {})()
        return {
            "node_count": getattr(kg, "node_count", 0),
            "edge_count": getattr(kg, "edge_count", 0),
            "stats": stats,
        }

    # ------------------------------------------------------------------
    # server lifecycle
    # ------------------------------------------------------------------
    def _start_http(self, host: str, port: int) -> HTTPServer:
        """Start the blocking ``ThreadingHTTPServer`` in a daemon thread."""
        handler_factory = type(
            "_DashboardHandler",
            (_DashboardHTTPHandler,),
            {"service": self},
        )
        server = HTTPServer((host, port), handler_factory)
        self._http_server = server
        thread = threading.Thread(
            target=server.serve_forever, daemon=True, name="dash-http"
        )
        thread.start()
        self._http_thread = thread
        logger.info("HTTP dashboard listening on http://%s:%s", host, port)
        return server

    async def _start_websocket(self, host: str, port: int) -> None:
        """Start the optional async WebSocket server on the NEXT port."""
        if not _HAS_WEBSOCKETS:
            logger.info(
                "WebSocket unavailable — install websockets package for WS support"
            )
            return
        ws_port = port + 1

        async def ws_handler(conn: WSConnection) -> None:
            interval = self._config.refresh_interval
            try:
                while True:
                    snapshot = self.build_snapshot()
                    await conn.send(json.dumps(snapshot.to_dict(), default=str))
                    await asyncio.sleep(interval)
            except Exception:
                pass

        self._ws_server = await websockets.serve(ws_handler, host, ws_port)
        logger.info("WebSocket server listening on ws://%s:%s", host, ws_port)

    def run(
        self,
        host: str | None = None,
        port: int | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        """Start the dashboard server.

        Blocks the current thread.  The REST API is served via stdlib
        ``HTTPServer``; WebSocket live updates run on *port* + 1 via the
        optional ``websockets`` library.
        """
        cfg = self._config
        host = host or cfg.host
        port = port or cfg.port

        self._start_http(host, port)

        if loop is None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Schedule WebSocket startup in the user-provided (or new) loop.
        loop.create_task(self._start_websocket(host, port))

        # Keep the loop alive.
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stop all servers."""
        self._stop_sse = True
        self._sse_event.set()
        if self._http_server:
            self._http_server.shutdown()
        if self._ws_server:
            self._ws_server.close()


__all__ = [
    "DashboardService",
    "DashboardSnapshot",
    "DashboardConfig",
]
