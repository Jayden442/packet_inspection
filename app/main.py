from fastapi import FastAPI
from .state import traffic_statistics
from src.analyzer import analyze_packet
from scapy.all import AsyncSniffer
# Create FastAPI app instance
app = FastAPI()



@app.get("/")
def read_root():
    return {"message": "Welcome to the NIDS API!"}

@app.get("/stats")
def get_short_stats():
    return traffic_statistics.get_short_summary()

@app.get("/stats/detailed")
def get_long_stats():
    return traffic_statistics.get_detailed_summary()

def process_packet(packet):
    packet_info = analyze_packet(packet)
    if packet_info is not None:
        traffic_statistics.add_packet(packet_info)
        
sniffer = AsyncSniffer(iface="eth0",prn=process_packet, store=False)
sniffer.start()