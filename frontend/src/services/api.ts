export interface TrafficRecord {
    id: number;
    timestamp: string;
    interval_seconds: number;
    total_packets: number;
    total_bytes: number;
    tcp_packets: number;
    udp_packets: number;
    icmp_packets: number;
    syn_packets: number;
    dns_queries: number;
}

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export async function getTrafficHistory(
    start: string,
    end: string,
    limit: number = 250
): Promise<TrafficRecord[]> {
    const params = new URLSearchParams({
        start,
        end,
        limit: limit.toString(),
    });

    const response = await fetch(
        `${API_URL}/statistics/history?${params.toString()}`
    );

    if (!response.ok) {
        throw new Error(`Failed to fetch traffic history: ${response.status}`);
    }

    return response.json();
}
export async function fetchStatistics() {
    const response = await fetch(`${API_URL}/statistics/summary`);

    if (!response.ok) {
        throw new Error("Failed to fetch statistics");
    }

    return response.json();
}

export async function fetchAlerts() {
    const response = await fetch(`${API_URL}/alerts`);

    if (!response.ok) {
        throw new Error("Failed to fetch alerts");
    }

    return response.json();
}