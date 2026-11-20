import "./App.css";
import { useEffect, useState } from "react";
import type { TrafficRecord } from "./services/api";
import { getTrafficHistory } from "./services/api";
import TrafficChart from "./components/TrafficChart";
import MetricCard from "./components/MetricCard";

function App() {
  const [records, setRecords] = useState<TrafficRecord[]>([]);
    const [loading, setLoading] = useState(true);
    const [statsError, setStatsError] = useState<string | null>(null);

    // Fetch traffic statistics when the dashboard loads.
    useEffect(() => {
        let cancelled = false;

        async function refreshStats() {
            try {
                const end = new Date();
                const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);

                const newRecords = await getTrafficHistory(
                    start.toISOString(),
                    end.toISOString()
                );

                if (cancelled) return;

                setRecords(newRecords);
                setStatsError(null);
            } catch (err) {
                if (!cancelled) {
                    setStatsError(
                        err instanceof Error
                            ? err.message
                            : "Failed to load statistics."
                    );
                }
            } finally {
                if (!cancelled) {
                    setLoading(false);
                }
            }
        }

        refreshStats();

        // Refresh statistics every 60 seconds.
        const intervalId = window.setInterval(refreshStats, 60_000);

        return () => {
            cancelled = true;
            window.clearInterval(intervalId);
        };
    }, []);

    // Find the most recent statistics record.
    const latestStats = records.reduce<TrafficRecord | null>(
        (newest, record) => {
            if (!newest) return record;

            return new Date(record.timestamp).getTime() >
                new Date(newest.timestamp).getTime()
                ? record
                : newest;
        },
        null
    );
    
    return (
        <div className="dashboard">

            {/* Sidebar */}
            <aside className="sidebar">
                <h2 className="sidebar-logo">NIDS</h2>

                <nav>
                    <a className="nav-link active" href="#">
                        Dashboard
                    </a>

                    <a className="nav-link" href="#">
                        Traffic
                    </a>

                    <a className="nav-link" href="#">
                        Alerts
                    </a>

                    <a className="nav-link" href="#">
                        DNS Monitoring
                    </a>
                </nav>
            </aside>

            {/* Main content */}
            <main className="main-content">

                {/* Header */}
                <header className="dashboard-header">
                    <div>
                        <h1>Network Monitoring</h1>
                        <p>Network activity overview</p>
                    </div>

                    <div className="monitoring-status">
                        <span className="status-dot"></span>
                        Monitoring Active
                    </div>
                </header>

                {/* Statistics */}
                <section className="metrics-grid">
                    <MetricCard
                        title="Total Packets"
                        value={latestStats?.total_packets ?? 0}
                        description="Packets captured"
                    />

                    <MetricCard
                        title="TCP Packets"
                        value={latestStats?.tcp_packets ?? 0}
                        description="TCP traffic captured"
                    />

                    <MetricCard
                        title="UDP Packets"
                        value={latestStats?.udp_packets ?? 0}
                        description="UDP traffic captured"
                    />

                    <MetricCard
                        title="ICMP Packets"
                        value={latestStats?.icmp_packets ?? 0}
                        description="ICMP traffic captured"
                    />
                </section>

                {/* Placeholder sections */}
                <section className="content-section">
                    <h2>Traffic Overview</h2>

                    {loading && records.length === 0 ? (
                        <p>Loading traffic data...</p>
                    ) : statsError && records.length === 0 ? (
                        <p>Error loading traffic data: {statsError}</p>
                    ) : (
                        <>
                            {statsError && (
                                <p>Error updating statistics: {statsError}</p>
                            )}
                            <TrafficChart records={records} />
                        </>
                    )}
                </section>

                <section className="content-section">
                    <h2>Recent Alerts</h2>
                    <p>Recent security alerts will appear here.</p>
                </section>

            </main>
        </div>
    );
}

export default App;