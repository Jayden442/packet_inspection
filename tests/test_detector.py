import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from connection_tracker import Connection, ConnectionState
from detector import Detector
from source_ip import SourceIP


class FakeStatistics:
    def __init__(self, source_ips=(), dns_statistics=None):
        self.source_ips = list(source_ips)
        self.dns_statistics = dns_statistics or {}

    def get_source_ips(self):
        return self.source_ips


def make_connection(state, port):
    return Connection(
        src_ip="192.0.2.1",
        src_port=port,
        dst_ip="198.51.100.2",
        dst_port=443,
        start_time=1,
        last_activity=1,
        state=state,
    )


def test_detect_port_scan_alerts_once_when_unique_port_threshold_is_exceeded():
    source_ip = SourceIP("192.0.2.1")
    source_ip.dest_ports = {80: 1, 443: 2, 8080: 3}
    detector = Detector(port_scan_threshold=2, syn_flood_threshold=0.5)
    stats = FakeStatistics([source_ip])

    detector.detect_port_scan(stats)
    detector.detect_port_scan(stats)

    alerts = detector.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "Port Scan"
    assert alerts[0].description == "3 unique destination ports accessed by 192.0.2.1"
    assert alerts[0].packet_info is None


def test_detect_port_scan_does_not_alert_at_threshold_or_for_no_sources():
    source_ip = SourceIP("192.0.2.1")
    source_ip.dest_ports = {80: 1, 443: 2}
    detector = Detector(port_scan_threshold=2, syn_flood_threshold=0.5)

    detector.detect_port_scan(FakeStatistics([source_ip]))
    detector.detect_port_scan(FakeStatistics())

    assert detector.get_alerts() == []


def test_detect_syn_flood_uses_current_and_incomplete_connections():
    tracker = SimpleNamespace(
        get_current_connections=lambda: (
            [make_connection(ConnectionState.SYN_ACK_RECEIVED, port) for port in range(60)]
            + [make_connection(ConnectionState.ESTABLISHED, port) for port in range(60, 100)]
        ),
        get_incomplete_connections=lambda: [
            make_connection(ConnectionState.SYN_ACK_RECEIVED, 100)
        ],
    )
    detector = Detector(port_scan_threshold=10, syn_flood_threshold=0.5)

    detector.detect_syn_flood(tracker)

    alerts = detector.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "SYN Flood"
    assert alerts[0].description == "61 SYN-ACK flags compared to 40 established connections recently"
    assert alerts[0].packet_info is None


def test_detect_syn_flood_requires_minimum_count_and_ratio_above_threshold():
    detector = Detector(port_scan_threshold=10, syn_flood_threshold=0.6)
    below_minimum = SimpleNamespace(
        get_current_connections=lambda: [
            make_connection(ConnectionState.SYN_ACK_RECEIVED, port) for port in range(99)
        ],
        get_incomplete_connections=lambda: [],
    )
    at_ratio_threshold = SimpleNamespace(
        get_current_connections=lambda: (
            [make_connection(ConnectionState.SYN_ACK_RECEIVED, port) for port in range(60)]
            + [make_connection(ConnectionState.ESTABLISHED, port) for port in range(60, 100)]
        ),
        get_incomplete_connections=lambda: [],
    )

    detector.detect_syn_flood(below_minimum)
    detector.detect_syn_flood(at_ratio_threshold)

    assert detector.get_alerts() == []


def test_detect_dns_tunneling_alerts_when_all_thresholds_are_met():
    dns_stats = SimpleNamespace(
        query_count=50,
        average_subdomain_entropy=3.0,
        average_query_length=50,
        unique_subdomains=40,
    )
    detector = Detector(port_scan_threshold=10, syn_flood_threshold=0.5)

    detector.detect_dns_tunneling(FakeStatistics(dns_statistics={"192.0.2.1": dns_stats}))

    alerts = detector.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "DNS Tunnelling"
    assert alerts[0].description == "Potential DNS Tunnelling attempt by ip address 192.0.2.1"
    assert alerts[0].packet_info is None


def test_detect_dns_tunneling_does_not_alert_below_a_threshold():
    dns_stats = SimpleNamespace(
        query_count=49,
        average_subdomain_entropy=3.0,
        average_query_length=50,
        unique_subdomains=40,
    )
    detector = Detector(port_scan_threshold=10, syn_flood_threshold=0.5)

    detector.detect_dns_tunneling(FakeStatistics(dns_statistics={"192.0.2.1": dns_stats}))

    assert detector.get_alerts() == []


def test_get_alerts_returns_alerts_in_detection_order():
    detector = Detector(port_scan_threshold=1, syn_flood_threshold=0.5)
    source_ip = SourceIP("192.0.2.1")
    source_ip.dest_ports = {80: 1, 443: 2}

    detector.detect_port_scan(FakeStatistics([source_ip]))

    assert detector.get_alerts()[0].alert_type == "Port Scan"
