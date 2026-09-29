from fastapi import WebSocket
from typing import List
import json
import asyncio
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if not self.active_connections:
            from api.state import state
            state.is_processing = False

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
            
        data = json.dumps(message)
        failed_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception as e:
                logger.error(f"Failed to send message to websocket: {e}")
                failed_connections.append(connection)
                
        for connection in failed_connections:
            self.disconnect(connection)

manager = ConnectionManager()
