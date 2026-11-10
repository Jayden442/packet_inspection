import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packet_info import PacketInfo
from statistics import DNSStatistics, TrafficStatistics


def make_packet(timestamp=None, src_ip="192.0.2.1", dst_port=53,
                dns_query=None, dns_is_response=False):
    return PacketInfo(
        timestamp=time.time() if timestamp is None else timestamp,
        src_ip=src_ip,
        dst_ip="198.51.100.2",
        dst_port=dst_port,
        protocol="UDP",
        dns_query=dns_query,
        dns_is_response=dns_is_response,
    )


def test_dns_statistics_counts_queries_and_calculates_averages():
    stats = DNSStatistics()

    stats.update(make_packet(dns_query="abc.example.com."))
    stats.update(make_packet(dns_query="xy.example.com"))
    stats.update(make_packet(dns_query="example.com"))
    stats.update(make_packet(dns_query="ignored.example.com", dns_is_response=True))
    stats.update(make_packet(dns_query=None))
    stats.update(None)

    assert stats.query_count == 3
    assert stats.total_query_length == len("abc.example.com") + len("xy.example.com") + len("example.com")
    assert stats.average_query_length == stats.total_query_length / 3
    assert stats.subdomain_counter == {"abc": 1, "xy": 1}
    assert stats.unique_subdomains == 2
    assert stats.average_subdomain_entropy > 0


def test_dns_statistics_entropy_and_subdomain_extraction():
    stats = DNSStatistics()

    assert stats.calculate_entropy("aaaa") == 0
    assert stats.calculate_entropy("ab") == 1
    assert stats.get_subdomain("example.com") is None
    assert stats.get_subdomain("www.example.com") == "www"


def test_dns_statistics_add_packet_filters_and_prunes_old_queries(monkeypatch):
    now = time.time()
    monkeypatch.setattr("statistics.time.time", lambda: now)
    stats = DNSStatistics(time_window=10)

    stats.add_packet(make_packet(now - 20, dns_query="old.example.com"))
    stats.add_packet(make_packet(now - 2, dns_query="new.example.com"))
    stats.add_packet(make_packet(now - 1, dns_query="response.example.com", dns_is_response=True))
    stats.add_packet(make_packet(now, dns_query=None))

    assert len(stats.packet_info_list) == 2
    assert stats.query_count == 2

    stats.remove_outdated_packets()

    assert len(stats.packet_info_list) == 1
    assert stats.query_count == 1
    assert stats.total_query_length == len("new.example.com")
    assert stats.subdomain_counter == {"new": 1}


def test_dns_statistics_empty_averages_are_zero():
    stats = DNSStatistics()

    assert stats.average_query_length == 0
    assert stats.average_subdomain_entropy == 0
    assert stats.unique_subdomains == 0


def test_traffic_statistics_tracks_sources_packets_and_dns_queries():
    stats = TrafficStatistics()
    packet = make_packet(dns_query="www.example.com")

    stats.add_packet(None)
    stats.add_packet(packet)

    assert stats.get_num_packets() == 1
    assert len(stats.get_source_ips()) == 1
    source_ip = stats.get_source_ips()[0]
    assert source_ip.ip_address == "192.0.2.1"
    assert source_ip.packet_count == 1
    assert source_ip.get_dest_port_count() == 1
    assert stats.dns_statistics["192.0.2.1"].query_count == 1


def test_traffic_statistics_excludes_packets_without_source_ip():
    stats = TrafficStatistics()
    stats.add_packet(make_packet(src_ip=None))

    assert stats.get_num_packets() == 1
    assert stats.get_source_ips() == []
    assert stats.dns_statistics == {}


def test_traffic_statistics_expires_old_packets_and_sources(monkeypatch):
    now = time.time()
    monkeypatch.setattr("statistics.time.time", lambda: now)
    stats = TrafficStatistics(time_window=10)
    stats.add_packet(make_packet(now - 20, dns_query="old.example.com"))
    stats.add_packet(make_packet(now - 2, dst_port=443, dns_query="new.example.com"))

    assert stats.get_num_packets() == 1
    assert len(stats.get_source_ips()) == 1
    assert stats.get_source_ips()[0].packet_count == 1
