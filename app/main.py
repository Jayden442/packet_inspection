from contextlib import asynccontextmanager
from http.client import HTTPException
from fastapi import FastAPI
from .state import traffic_statistics
from src.analyzer import analyze_packet
from scapy.all import AsyncSniffer
import storage.database as db
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

    try:
        yield
    finally:
        if sniffer.running:
            sniffer.stop()

app = FastAPI(lifespan=lifespan)
@app.get("/")
def read_root():
    return {"message": "Welcome to the NIDS API!"}

@app.get("/stats")
def get_short_stats():
    return traffic_statistics.get_short_summary()

@app.get("/stats/detailed")
def get_long_stats():
    return traffic_statistics.get_detailed_summary()

@app.get("/alerts")
def get_alerts(limit: int = 100, severity: str = None, alert_type: str = None, acknowledged: bool = None):
    limit = max(1, min(limit, 250))  # Ensure limit is between 1 and 250
    alerts = db.get_alerts(limit=limit, severity=severity, alert_type=alert_type, acknowledged=acknowledged)
    return {"alerts": alerts}

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
def process_packet(packet):
    packet_info = analyze_packet(packet)
    if packet_info is not None:
        traffic_statistics.add_packet(packet_info)
        