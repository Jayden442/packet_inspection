from .alert import Alert, Severity
from .statistics import TrafficStatistics, DNSStatistics
from .connection_tracker import ConnectionTracker, ConnectionState
from .storage.database import save_alert
from time import datetime

CONNECTION_THRESHOLD = 100
QUERY_THRESHOLD = 50
AVG_QUERY_LEN_THRESHOLD = 50
UNIQUE_SUBDOMAINS_THRESHOLD = 40
AVG_ENTROPY_THRESHOLD = 3.0


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
                        packet_info=None,
                        timestamp=datetime.now(),
                        source_ip=source_ip.ip_address,
                        dest_ip=None,
                        severity=Severity.MEDIUM,
                    )
                    self.alerts.append(alert)
                    if not self.is_duplicate_alert(alert):
                        save_alert(alert)

    def detect_syn_flood(self, connection_tracker: ConnectionTracker):
        valid_connections = connection_tracker.get_current_connections()
        incomplete_connections = connection_tracker.get_incomplete_connections()

        current_syn_ack = 0
        incomplete_syn_ack = 0
        established = 0
        for connection in valid_connections:
            if connection.state == ConnectionState.SYN_ACK_RECEIVED:
                current_syn_ack += 1
            elif connection.state == ConnectionState.ESTABLISHED:
                established += 1
        for incomplete_connection in incomplete_connections:
            if incomplete_connection.state == ConnectionState.SYN_ACK_RECEIVED:
                incomplete_syn_ack += 1
        total_syn_ack = current_syn_ack + incomplete_syn_ack
        total_count = established + total_syn_ack

        if total_count > 0 and total_syn_ack / total_count > self.syn_flood_threshold and total_count >= CONNECTION_THRESHOLD:
            alert = Alert(
                alert_type="SYN Flood",
                description=f"{total_syn_ack} SYN-ACK flags compared to {established} established connections recently",
                packet_info=None,
                timestamp=datetime.now(),
                source_ip=None,
                dest_ip=None,
                severity=Severity.HIGH
            )
            self.alerts.append(alert)
            if not self.is_duplicate_alert(alert):
                save_alert(alert)
    def detect_dns_tunneling(self, statistics: TrafficStatistics):
        for ip, dns_stats in statistics.dns_statistics.items():
            if (
                dns_stats.query_count >= QUERY_THRESHOLD 
                and dns_stats.average_subdomain_entropy >= AVG_ENTROPY_THRESHOLD
                and dns_stats.average_query_length >= AVG_QUERY_LEN_THRESHOLD
                and dns_stats.unique_subdomains >= UNIQUE_SUBDOMAINS_THRESHOLD
            ):
                alert = Alert(
                    alert_type="DNS Tunnelling",
                    description=f"Potential DNS Tunnelling attempt by ip address {ip}",
                    packet_info=None,
                    timestamp=datetime.now(),
                    source_ip=ip,
                    dest_ip=None,
                    severity=Severity.HIGH
                )
                self.alerts.append(alert)
                if not self.is_duplicate_alert(alert):
                    save_alert(alert)
    def get_alerts(self):
        return self.alerts

    def is_duplicate_alert(self, new_alert: Alert):
        for alert in self.alerts:
            if (
                alert.alert_type == new_alert.alert_type
                and alert.source_ip == new_alert.source_ip
                and alert.destination_ip == new_alert.destination_ip
                and alert.description == new_alert.description
                and alert.severity == new_alert.severity
                and alert.acknowledged == False
            ):
                return True
        return False
