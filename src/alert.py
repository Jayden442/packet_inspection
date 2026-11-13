from enum import Enum


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

class Alert:
    def __init__(self, alert_type, timestamp, description, packet_info, source_ip=None, dest_ip=None, severity=Severity.LOW):
        self.alert_type = alert_type
        self.timestamp = timestamp
        self.description = description
        self.packet_info = packet_info
        self.source_ip = source_ip
        self.destination_ip = dest_ip
        self.severity = severity
        self.acknowledged = False

    def __str__(self):
        return f"[ALERT]: {self.alert_type}, Description: {self.description}, Packet Info: {self.packet_info}"

    def acknowledge(self):
        self.acknowledged = True
    