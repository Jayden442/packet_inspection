from packet_info import PacketInfo
from collections import deque
import time

class TrafficStatistics:
    def __init__(self,time_window=10):
        self.time_window = time_window
        self.packets = deque()

    def add_packet(self, packet_info: PacketInfo | None):
        if packet_info is None:
            return
        self.packets.append(packet_info)
        self.remove_outdated_packets()

    def remove_outdated_packets(self):
        cur_time = time.time()
        while (
            self.packets and cur_time - self.packets[0].timestamp > self.time_window
        ):
            self.packets.popleft()
    def get_num_packets(self):
        self.remove_outdated_packets()
        return len(self.packets)
    def print_stats(self):
        num_packets = self.get_num_packets()
        print(f'Monitoring window: {self.time_window}\nTotal packets:{num_packets}\nPackets per second: {num_packets/self.time_window}')
