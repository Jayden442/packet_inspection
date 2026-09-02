import threading
import time

from sniffer import sniff_packet
from analyzer import analyze_packet
from statistics import TrafficStatistics


def main():
    statistics = TrafficStatistics(time_window=10)
    sniffing_thread = threading.Thread(
        target=sniff_packet,
        args=(statistics.add_packet,),
        daemon=True
    )
    sniffing_thread.start()
    while True:
        time.sleep(10)
        statistics.print_stats()

if __name__ == "__main__":
    main()