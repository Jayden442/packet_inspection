from importlib import import_module
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

analyzer = import_module("analyzer")

def test_analyze_packet_returns_none_for_non_ip_packets():
    packet = MagicMock()
    packet.haslayer.return_value = False
    packet.__contains__.return_value = False

    assert analyzer.analyze_packet(packet) is None
    
def test_analyze_packet_returns_packet_info_for_ip_packets():
    packet = MagicMock()
    packet.haslayer.side_effect = lambda layer: layer in [analyzer.IP, analyzer.Ether, analyzer.TCP]
    packet.__contains__.side_effect = lambda layer: layer in [analyzer.IP, analyzer.Ether, analyzer.TCP]
    packet[analyzer.IP].src = "192.0.0.1"
    packet[analyzer.IP].dst = "192.0.0.2"
    packet[analyzer.Ether].src = "00:11:22:33:44:55"
    packet[analyzer.Ether].dst = "66:77:88:99:AA:BB"
    packet[analyzer.TCP].sport = 12345
    packet[analyzer.TCP].dport = 443
    
    assert isinstance(analyzer.analyze_packet(packet), analyzer.PacketInfo)