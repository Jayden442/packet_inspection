import "./MetricCard.css";

interface MetricCardProps {
    title: string,
    value: number,
    description: string
}

function MetricCard({ title, value, description }: MetricCardProps) {
    return (
        <div className="metric-card">
            <h3 className="metric-title">{title}</h3>
            <h1 className="metric-value">{value.toLocaleString()}</h1>
            <p className="metric-description">{description}</p>
        </div>
    );
}

export default MetricCard;