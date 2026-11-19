from datetime import datetime, timezone
from storage.database import save_statistics

class IntervalStatistics:
    def __init__(self):
        self.reset()

    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.source_ips = set()
        self.destination_ips = set()
        self.syn_packets = 0
        self.dns_queries = 0

    def add_packet(self, packet_info):
        self.total_packets += 1

        # Update the remaining counters using packet_info.
        if packet_info.protocol == "TCP":
            self.tcp_packets += 1
            if packet_info.tcp_flags & 0x02:  # SYN flag
                self.syn_packets += 1
        if packet_info.protocol == "UDP":
            self.udp_packets += 1
        if packet_info.protocol == "ICMP":
            self.icmp_packets += 1
        self.source_ips.add(packet_info.src_ip)
        self.destination_ips.add(packet_info.dst_ip)
        if packet_info.dns_query:
            self.dns_queries += 1
        self.total_bytes += packet_info.packet_length
    
    def make_snapshot(self):
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interval_seconds": 60,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "syn_packets": self.syn_packets,
            "dns_queries": self.dns_queries
        }
        save_statistics(snapshot=snapshot)
        print("Saved snapshot:", snapshot)
        self.reset()  # Reset after making a snapshot
        return snapshot
        