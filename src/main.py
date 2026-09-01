from sniffer import sniff_packet
from analyzer import process_packet
if __name__ == "__main__":
    # packets = sniff(count=10)
    sniff_packet(process_packet)