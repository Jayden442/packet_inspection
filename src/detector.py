from packet_info import PacketInfo
from statistics import TrafficStatistics


class Detector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.port_scan_ips = set()

    def detect_port_scan(self, statistics: TrafficStatistics):
        alerts = []
        for source_ip in statistics.get_source_ips():
            if source_ip.get_dest_port_count() > self.threshold:
                if source_ip.ip_address not in self.port_scan_ips:
                    self.port_scan_ips.add(source_ip.ip_address)
                    alerts.append(f"Port scan detected from {source_ip.ip_address}\n")
        return alerts
