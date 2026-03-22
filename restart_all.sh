#!/bin/bash
# Kill old processes
pkill -f "collector.py|intel_collector.py|classifier.py" 2>/dev/null

echo "Starting Pleriguard V2 services..."
source ~/.openclaw/workspace/pleriguard/v2/venv/bin/activate

# Start collector with restart logic
(while true; do
    echo "[$(date)] Starting collector..."
    python -u collectors/collector.py 2>&1 | tee -a logs/collector.log
    echo "[$(date)] Collector died, restarting in 5s..."
    sleep 5
done) &
COLLECTOR_PID=$!

# Start intel collector with restart logic  
(while true; do
    echo "[$(date)] Starting intel collector..."
    python -u collectors/intel_collector.py --loop 2>&1 | tee -a logs/intel.log
    echo "[$(date)] Intel collector died, restarting in 5s..."
    sleep 5
done) &
INTEL_PID=$!

# Start classifier with restart logic
(while true; do
    echo "[$(date)] Starting classifier..."
    python -u classification/classifier.py --loop 2>&1 | tee -a logs/classifier.log
    echo "[$(date)] Classifier died, restarting in 5s..."
    sleep 5
done) &
CLASSIFIER_PID=$!

# Start dashboard with restart logic
(while true; do
    echo "[$(date)] Starting dashboard..."
    python -u dashboard.py 2>&1 | tee -a logs/dashboard.log
    echo "[$(date)] Dashboard died, restarting in 5s..."
    sleep 5
done) &
DASHBOARD_PID=$!

echo "Services started:"
echo "  Collector: $COLLECTOR_PID"
echo "  Intel: $INTEL_PID" 
echo "  Classifier: $CLASSIFIER_PID"
echo "  Dashboard: $DASHBOARD_PID"

# Save PIDs for monitoring
echo "$COLLECTOR_PID" > pids/collector.pid
echo "$INTEL_PID" > pids/intel.pid
echo "$CLASSIFIER_PID" > pids/classifier.pid
echo "$DASHBOARD_PID" > pids/dashboard.pid

echo "Auto-restart enabled. Logs in logs/ directory."
