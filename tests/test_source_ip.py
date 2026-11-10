import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packet_info import PacketInfo
from source_ip import SourceIP


def make_packet(timestamp, dst_port=None):
    return PacketInfo(
        timestamp=timestamp,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        dst_port=dst_port,
    )


def test_source_ip_tracks_packet_metadata():
    source_ip = SourceIP("192.168.1.10")
    packet = make_packet(100.0, dst_port=80)

    source_ip.update(packet)

    assert source_ip.ip_address == "192.168.1.10"
    assert source_ip.packet_count == 1
    assert source_ip.first_seen == 100.0
    assert source_ip.last_seen == 100.0
    assert list(source_ip.packets) == [packet]


def test_add_dest_ignores_none_and_duplicate_ports():
    source_ip = SourceIP("192.168.1.10")

    source_ip.update(make_packet(10.0, dst_port=80))
    source_ip.add_dest(make_packet(11.0, dst_port=80))
    source_ip.add_dest(make_packet(12.0, dst_port=443))
    source_ip.add_dest(None)
    source_ip.add_dest(make_packet(13.0, dst_port=None))

    assert source_ip.dest_ports == {80: 10.0, 443: 12.0}
    assert source_ip.get_dest_port_count() == 2


def test_remove_outdated_packets_prunes_old_entries():
    current_time = time.time()
    source_ip = SourceIP("192.168.1.10")

    stale_packet = make_packet(current_time - 120.0, dst_port=80)
    recent_packet = make_packet(current_time - 5.0, dst_port=443)

    source_ip.update(stale_packet)
    source_ip.update(recent_packet)
    source_ip.add_dest(stale_packet)
    source_ip.add_dest(recent_packet)

    source_ip.remove_outdated_packets(30)

    assert source_ip.packet_count == 1
    assert list(source_ip.packets) == [recent_packet]
    assert source_ip.dest_ports == {443: current_time - 5.0}
