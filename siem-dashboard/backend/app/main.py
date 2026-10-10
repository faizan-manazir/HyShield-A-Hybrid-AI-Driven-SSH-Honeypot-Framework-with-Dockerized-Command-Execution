from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import os
import logging
from contextlib import asynccontextmanager

from app.database.connection import Base, engine
from app.services.log_watcher import LogWatcher
from app.services.event_processor import EventProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize DB tables
Base.metadata.create_all(bind=engine)

log_watcher = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global log_watcher
    cowrie_log_path = os.getenv("COWRIE_LOG_PATH", "cowrie.json")
    
    loop = asyncio.get_running_loop()
    event_processor = EventProcessor(loop=loop)
    
    log_watcher = LogWatcher(cowrie_log_path, event_processor.process_lines)
    log_watcher.start()
    
    yield
    
    if log_watcher:
        log_watcher.stop()

app = FastAPI(title="HyShield SIEM API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.services.websocket_manager import manager as ws_manager
from fastapi import WebSocket, WebSocketDisconnect

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

from app.api import dashboard, events, attackers, sessions, alerts, charts

app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(attackers.router)
app.include_router(sessions.router)
app.include_router(alerts.router)
app.include_router(charts.router)

@app.get("/")
def root():
    return {"status": "ok", "message": "HyShield SIEM API is running"}
