from contextlib import asynccontextmanager
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from http.client import HTTPException
from fastapi import FastAPI
from .state import traffic_statistics, interval_stats
from src.analyzer import analyze_packet
from scapy.all import AsyncSniffer
from app.loop import snapshot_loop, retention_loop
import asyncio
import storage.database as db
from fastapi.middleware.cors import CORSMiddleware


# Create FastAPI app instance

@asynccontextmanager
async def lifespan(app: FastAPI):
    sniffer = AsyncSniffer(
        iface="wlx00e02d1b1faa",
        prn=process_packet,
        store=False,
    )
    print("Starting packet sniffer...")
    db.initialize_database()  # Initialize the database

    sniffer.start()
    snapshot_task = asyncio.create_task(snapshot_loop())
    retention_task = asyncio.create_task(retention_loop())

    try:
        yield
    finally:
        snapshot_task.cancel()
        retention_task.cancel()
        await asyncio.gather(snapshot_task, retention_task, return_exceptions=True)
        if sniffer.running:
            sniffer.stop()

def normalize_datetime(dt: datetime, assumed_timezone=ZoneInfo("America/Toronto")):
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=assumed_timezone).astimezone(timezone.utc)

    return dt.astimezone(timezone.utc).isoformat()
        

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to the NIDS API!"}

@app.get("/statistics")
def get_short_stats():
    return traffic_statistics.get_short_summary()

@app.get("/statistics/detailed")
def get_long_stats():
    return traffic_statistics.get_detailed_summary()

@app.get("/alerts")
def get_alerts(limit: int = 100, severity: str = None, alert_type: str = None, acknowledged: bool = None, start=None, end=None):
    start = normalize_datetime(start) if start else None
    end = normalize_datetime(end) if end else None
    if start and end and start > end:
        raise HTTPException(
            status_code=400,
            detail="Start must be earlier than end"
        )
    return db.get_alerts(
        limit=limit,
        severity=severity,
        alert_type=alert_type,
        acknowledged=acknowledged,
        start=start,
        end=end
    )

@app.get("/alerts/{alert_id}")
def retrieve_alert(alert_id: int):
    alert = db.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )
    return alert

@app.patch("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    success = db.change_alert_acknowledgement(alert_id, acknowledge=True)
    if success:
        return {"message": f"Alert {alert_id} acknowledged successfully."}
    else:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )
@app.patch("/alerts/{alert_id}/unacknowledge")
def unacknowledge_alert(alert_id: int):
    success = db.change_alert_acknowledgement(alert_id, acknowledge=False)
    if success:
        return {"message": f"Alert {alert_id} unacknowledged successfully."}
    else:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

@app.get("/statistics/summary")
def statistics_summary(start: datetime, end: datetime):
    start = normalize_datetime(start)
    end = normalize_datetime(end)
    if start > end:
        raise HTTPException(
            status_code=400,
            detail="Start must be earlier than end"
        )
    return db.get_statistics_summary(start, end)

@app.get("/statistics/history")
def get_statistics_history(start: datetime, end: datetime, limit=250):
    start = normalize_datetime(start)
    end = normalize_datetime(end)
    if start > end:
        raise HTTPException(
            status_code=400,
            detail="Start must be earlier than end"
        )
    return db.get_statistics_timeframe(start, end, limit)

def process_packet(packet):
    packet_info = analyze_packet(packet)
    if packet_info is not None:
        traffic_statistics.add_packet(packet_info)
        interval_stats.add_packet(packet_info)

        