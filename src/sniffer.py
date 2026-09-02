from scapy.sendrecv import sniff
from analyzer import analyze_packet


def sniff_packet(callback_func):
    def process_packet(packet):
        packet_info = analyze_packet(packet)
        callback_func(packet_info)
    sniff(
        prn=process_packet,
        store=False
    )