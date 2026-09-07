import threading
import time
import argparse

from detector import Detector
from sniffer import sniff_packet
from analyzer import analyze_packet
from statistics import TrafficStatistics
from connection_tracker import ConnectionTracker

CONNECTION_TIMEOUT = 20  # seconds

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer and Analyzer")
    parser.add_argument("--time-window", type=int, default=10, help="Time window for traffic statistics (seconds)")
    parser.add_argument("--threshold", type=int, default=40, help="Port scan detection threshold")
    args = parser.parse_args()
    statistics = TrafficStatistics(time_window=args.time_window)
    connection_tracker = ConnectionTracker(timeout=CONNECTION_TIMEOUT)
    sniffing_thread = threading.Thread(
        target=sniff_packet,
        args=(statistics.add_packet, connection_tracker.process_packet),
        daemon=True
    )
    sniffing_thread.start()
    
    detector = Detector(threshold=args.threshold)
    while True:
        time.sleep(10)
        statistics.print_stats()
        detector.detect_port_scan(statistics)
        detector.detect_syn_flood(connection_tracker)
        alerts = detector.get_alerts()
        for alert in alerts:
            print(alert)

if __name__ == "__main__":
    main()
