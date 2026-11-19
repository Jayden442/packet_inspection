const API_URL = import.meta.env.VITE_API_URL;

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