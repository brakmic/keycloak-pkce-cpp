#!/bin/bash

echo "Finding nginx processes..."
NGINX_PIDS=$(ps aux | grep '[n]ginx' | awk '{print $2}')

if [ -z "$NGINX_PIDS" ]; then
    echo "No nginx processes found."
    exit 0
fi

echo "Found nginx PIDs: $NGINX_PIDS"
echo "Stopping nginx processes..."

# Try graceful shutdown first
for pid in $NGINX_PIDS; do
    echo "Sending SIGTERM to PID $pid"
    kill -TERM $pid 2>/dev/null
done

# Wait a bit
sleep 2

# Check if any processes remain and force kill them
REMAINING_PIDS=$(ps aux | grep '[n]ginx' | awk '{print $2}')
if [ ! -z "$REMAINING_PIDS" ]; then
    echo "Some processes still running. Force killing..."
    for pid in $REMAINING_PIDS; do
        echo "Sending SIGKILL to PID $pid"
        kill -9 $pid 2>/dev/null
    done
fi

# Verify all processes are gone
sleep 1
if pgrep nginx >/dev/null; then
    echo "ERROR: Some nginx processes could not be killed!"
    exit 1
else
    echo "All nginx processes stopped successfully."
    exit 0
fi
