from alert import Alert
from statistics import TrafficStatistics


class Detector:
    def __init__(self, port_scan_threshold, syn_flood_threshold):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.port_scan_ips = set()
        self.alerts = []

    def detect_port_scan(self, statistics: TrafficStatistics):
        for source_ip in statistics.get_source_ips():
            if source_ip.get_dest_port_count() > self.port_scan_threshold:
                if source_ip.ip_address not in self.port_scan_ips:
                    self.port_scan_ips.add(source_ip.ip_address)
                    num_ports = source_ip.get_dest_port_count()
                    alert = Alert(
                        alert_type="Port Scan",
                        description=f"{num_ports} unique destination ports accessed by {source_ip.ip_address}",
                        packet_info=None
                    )
                    self.alerts.append(alert)
        return self.alerts

    def detect_syn_flood(self, statistics: TrafficStatistics):
        for source_ip in statistics.get_source_ips():
            syn_packets = [pkt for pkt in source_ip.packets if pkt.protocol == 'TCP' and pkt.flags == 'S']
            ack_packets = [pkt for pkt in source_ip.packets if pkt.protocol == 'TCP' and pkt.flags == 'A']
            if len(syn_packets) / len(ack_packets) > self.syn_flood_threshold and len(syn_packets) > 10:
                alert = Alert(
                    alert_type="SYN Flood",
                    description=f"{len(syn_packets)} SYN packets detected from {source_ip.ip_address} compared to {len(ack_packets)} ACK packets",
                    packet_info=None
                )
                self.alerts.append(alert)
        return self.alerts
