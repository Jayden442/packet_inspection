import "./Alerts.css"
import { useEffect, useState } from "react";
import { fetchAlerts } from "../services/api";

interface Alert {
    id: number;
    timestamp: string;
    alert_type: string;
    severity: string;
    source_ip: string;
    destination_ip: string;
    description: string;
    acknowledged: 0 | 1;
}

function Alerts() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    useEffect(() => {
        async function loadAlerts() {
            try{
                const data = await fetchAlerts();
                setAlerts(data)
            }
            catch (error) {
                console.error("Could not load alerts: ", error)
            }
        }
        
        loadAlerts();
    }, []);
    const highCount = alerts.filter(
        (alert) => alert.severity === "HIGH"
    ).length
    const mediumCount = alerts.filter(
        (alert) => alert.severity === "MEDIUM"
    ).length
    const lowCount = alerts.filter(
        (alert) => alert.severity === "LOW"
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
                <h3>{alert.alert_type}</h3>

                <p>{alert.description}</p>
                <p>Source: {alert.source_ip}</p>

                <span
                    className={`severity severity-${alert.severity.toLowerCase()}`}
                >
                    {alert.severity}
                </span>

                <p className="alert-timestamp">
                    {alert.timestamp.toLocaleString()}
                </p>
            </div>
))}
        </div>
    );
}

export default Alerts;