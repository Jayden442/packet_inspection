import "./Alerts.css"

type Alert = {
    id: number;
    title: string;
    description: string;
    severity: "Low" | "Medium" | "High";
    timestamp: string;
};



function Alerts() {
    const alerts: Alert[] = [
        {
            id: 1,
            title: "Port Scan Detected",
            description: "Multiple ports scanned by 192.168.1.100",
            severity: "High",
            timestamp: "2026-11-20 22:10:00",
        },
        {
            id: 2,
            title: "DNS Anomaly",
            description: "Unusually long DNS queries detected",
            severity: "Medium",
            timestamp: "2026-11-20 21:58:00",
        },
        {
            id: 3,
            title: "SYN Flood Detection",
            description: "High number of incomplete TCP connections detected",
            severity: "High",
            timestamp: "2026-11-20 21:55:00",
        },
    ];
    const highCount = alerts.filter(
        (alert) => alert.severity === "High"
    ).length
    const mediumCount = alerts.filter(
        (alert) => alert.severity === "Medium"
    ).length
    const lowCount = alerts.filter(
        (alert) => alert.severity === "Low"
    ).length
    const totalCount = alerts.length
    return (
        <div className="alerts-container">
            <div className="alert-summary">
                <div className="summary-card">
                    <span className="summary-label">High</span>
                    <span className="summary-value high-text">{highCount}</span>
                </div>

            <div className="summary-card">
                <span className="summary-label">Medium</span>
                <span className="summary-value medium-text">{mediumCount}</span>
            </div>

            <div className="summary-card">
                <span className="summary-label">Low</span>
                <span className="summary-value low-text">{lowCount}</span>
            </div>

            <div className="summary-card">
                <span className="summary-label">Total</span>
                <span className="summary-value">{totalCount}</span>
            </div>
        </div>
        <h2>Alerts</h2>

        {alerts.map((alert) => (
            <div
                key={alert.id}
                className={`alert alert-${alert.severity.toLowerCase()}`}
            >
                <h3>{alert.title}</h3>

                <p>{alert.description}</p>

                <span
                    className={`severity severity-${alert.severity.toLowerCase()}`}
                >
                    {alert.severity}
                </span>

                <p className="alert-timestamp">
                    {alert.timestamp}
                </p>
            </div>
))}
        </div>
    );
}

export default Alerts;