from scapy.sendrecv import sniff

packet_count = 0

def print_packet(packet):
    global packet_count
    packet_count += 1
    print(f"{packet_count}: {packet.summary()}")
def sniff_packet(callback_func):
    sniff(store=0, prn=callback_func)
