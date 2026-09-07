from scapy.sendrecv import sniff
from analyzer import analyze_packet


def sniff_packet(statistics_callback, connection_tracker_callback):
    def process_packet(packet):
        packet_info = analyze_packet(packet)
        statistics_callback(packet_info)
        connection_tracker_callback(packet_info)
    sniff(
        prn=process_packet,
        store=False
    )
