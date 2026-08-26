from scapy.all import sniff


def process_packet(packet):
    print(packet.summary())


if __name__ == "__main__":
    sniff(iface="eth0", prn=process_packet)