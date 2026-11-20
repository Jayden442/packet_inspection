import { useEffect, useState } from "react";

import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from "recharts";

import { getTrafficHistory } from "../services/api";
import type { TrafficRecord } from "../services/api";

import "./TrafficChart.css";

interface ChartData {
    time: string;
    packets: number;
}

interface TrafficChartProps {
    records: TrafficRecord[];
}

function TrafficChart({records}: TrafficChartProps) {
    const trafficData: ChartData[] = records
        .sort(
            (a, b) =>
                new Date(a.timestamp).getTime() -
                new Date(b.timestamp).getTime()
        )
        .map((record) => ({
            time: new Date(record.timestamp).toLocaleTimeString(
                [],
                { hour: "2-digit", minute: "2-digit" }
            ),
            packets: record.total_packets,
        }));


    if (trafficData.length === 0) {
        return <p>No traffic data available for this period.</p>;
    }

    return (
        <div className="traffic-chart">
            <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trafficData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Line
                        type="monotone"
                        dataKey="packets"
                        stroke="#38bdf8"
                        strokeWidth={2}
                        dot={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

export default TrafficChart;