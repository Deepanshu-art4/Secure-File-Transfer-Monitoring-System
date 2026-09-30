import json
from typing import List, Dict, Any
from fastapi import WebSocket


class ConnectionManager:
    """
    WebSocket Connection Manager for Real-Time SOC Telemetry.
    Broadcasts live file transfer events, security violations, and alert status changes.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Transmits JSON telemetry to all connected SOC analysts and dashboards."""
        text = json.dumps(message, default=str)
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(text)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()
