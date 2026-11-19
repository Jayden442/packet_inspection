interface MetricCardProps {
    title: string;
    value: number;
    description: string;
}

function MetricCard({ title, value, description }: MetricCardProps){
    return (
        <div>
            <h3>{title}</h3>
            <h1>{value.toLocaleString()}</h1>
            <p>{description}</p>
        </div>
    );
}

export default MetricCard;