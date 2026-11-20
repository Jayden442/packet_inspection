# Network Intrusion Detection System (NIDS)

A network intrusion detection system built with Python and Scapy to monitor network traffic, collect statistics, detect potentially suspicious activity, and display network information through a web-based dashboard.

## Overview

This project aims to provide real-time network monitoring and basic intrusion detection capabilities. It captures network packets, analyzes traffic patterns, tracks network connections, and identifies potentially malicious activity.

The system also includes a web dashboard that communicates with the backend through a REST API, allowing users to view traffic statistics and monitor network activity.

## Features

### Network Monitoring
- Capture network packets using Scapy.
- Extract packet information, including source and destination IP addresses, ports, protocols, and TCP flags.
- Track TCP, UDP, and ICMP traffic.
- Collect traffic statistics over configurable time windows.

### Intrusion Detection
- Track TCP connection states.
- Identify potentially suspicious connection patterns.
- Detect SYN flood activity.
- Monitor network activity for potential port scans.
- Collect DNS statistics, including query frequency, query length, and subdomain characteristics, to support DNS tunneling detection.

### Alert Management
- Generate alerts for detected suspicious activity.
- Store alerts persistently.
- Support alert acknowledgement and management.

### Data Persistence
- Store historical traffic statistics in SQLite.
- Retain monitoring data for later analysis.
- Retrieve historical statistics through API endpoints.

### Web Dashboard
- React and TypeScript frontend.
- Display traffic metrics, including total packets and protocol-specific counts.
- Visualize historical network traffic using line charts.
- Automatically refresh dashboard data every 60 seconds.
- Communicate with the backend through a REST API.

## Technologies

| Component | Technologies |
|---|---|
| Packet Capture | Python, Scapy |
| Backend API | FastAPI |
| Database | SQLite |
| Frontend | React, TypeScript |
| Build Tool | Vite |
| Data Visualization | Recharts |

## Project Structure

```text
packet_inspection/
├── app/
│   ├── main.py
│   └── ...
├── data/
│   └── nids.db
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── MetricCard.tsx
│   │   │   ├── MetricCard.css
│   │   │   ├── TrafficChart.tsx
│   │   │   └── TrafficChart.css
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── App.tsx
│   │   ├── App.css
│   │   └── main.tsx
│   ├── package.json
│   └── ...
├── venv/
└── README.md
```

*Note: The backend structure is abbreviated. Adjust it to match the actual files in your repository.*

## Installation

### Prerequisites

- Python 3
- Node.js and npm
- Ubuntu or another Linux environment
- Network interface access for packet capture

### 1. Clone the Repository

```bash
git clone <repository-url>
cd packet_inspection
```

### 2. Set Up the Python Environment

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

### 3. Configure the Frontend

Navigate to the frontend directory:

```bash
cd frontend
npm install
```

Create a `.env` file in the `frontend/` directory:

```env
VITE_API_URL=http://127.0.0.1:8000
```

Return to the project root:

```bash
cd ..
```

## Running the Application

The backend and frontend run independently.

### 1. Start the Backend

From the project root:

```bash
source venv/bin/activate
python -m uvicorn app.main:app --reload
```

The FastAPI backend will be available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

### 2. Start the Frontend

Open another terminal:

```bash
cd frontend
npm run dev
```

The dashboard will be available at:

```text
http://localhost:5173
```

## API Endpoints

The backend exposes REST endpoints for retrieving monitoring data.

| Endpoint | Method | Description |
|---|---|---|
| `/statistics/history` | GET | Retrieve historical traffic statistics |
| `/statistics/summary` | GET | Retrieve a summary of traffic statistics |
| `/alerts` | GET | Retrieve generated security alerts |

Historical statistics can be filtered using `start` and `end` query parameters.

Example:

```text
/statistics/history?start=<start-timestamp>&end=<end-timestamp>
```

Refer to the FastAPI documentation at `/docs` for available parameters and additional endpoints.

## Dashboard

The React dashboard provides a graphical interface for monitoring network activity.

Current dashboard components include:

- **Metric Cards:** Display the latest packet counts for total, TCP, UDP, and ICMP traffic.
- **Traffic Overview:** Visualize historical packet counts over time.
- **Recent Alerts:** Dashboard section intended to display security alerts.

Traffic statistics are periodically retrieved from the backend and refreshed every 60 seconds.

## Future Improvements

Potential areas for further development include:

- Expand intrusion detection rules and detection accuracy.
- Implement DNS tunneling detection.
- Improve port scan and SYN flood detection.
- Add filtering, sorting, and acknowledgement controls for alerts.
- Expand dashboard visualizations and historical traffic analysis.
- Add configurable detection thresholds.
- Improve alert severity classification.
- Add network traffic filtering by protocol, IP address, and time range.

## Disclaimer

This project is intended for educational and network security research purposes. Only capture and analyze network traffic on systems and networks where you have appropriate authorization.