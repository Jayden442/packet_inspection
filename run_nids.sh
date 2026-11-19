#!/bin/bash

set -e

# Resolve the project directory (where this script is located)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to the virtual environment's Python executable
PYTHON="$PROJECT_DIR/venv/bin/python"

# Check that the virtual environment exists
if [ ! -x "$PYTHON" ]; then
    echo "Error: Python executable not found at $PYTHON"
    exit 1
fi

# Grant packet capture capabilities
echo "Granting packet capture capabilities..."
sudo setcap cap_net_raw+eip "$(readlink -f "$PYTHON")"

# Verify capabilities
echo "Current capabilities:"
getcap "$(readlink -f "$PYTHON")"

# Start the NIDS
echo "Starting NIDS..."
cd "$PROJECT_DIR"
exec "$PYTHON" -m uvicorn app.main:app --reload
