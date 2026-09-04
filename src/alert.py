class Alert:
    def __init__(self, alert_type, description, packet_info):
        self.alert_type = alert_type
        self.description = description
        self.packet_info = packet_info

    def __str__(self):
        return f"[ALERT]: {self.alert_type}, Description: {self.description}, Packet Info: {self.packet_info}"