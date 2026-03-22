#!/bin/bash
# Auto-monitoring script that runs every 5 minutes

LOG_FILE="logs/monitor.log"
ALERT_THRESHOLD=80  # Backlog percentage alert threshold

while true; do
    echo "=== $(date) ===" >> $LOG_FILE
    
    # Run monitor and capture output
    MONITOR_OUTPUT=$(python monitor.py 2>&1)
    echo "$MONITOR_OUTPUT" >> $LOG_FILE
    
    # Check for high backlog
    BACKLOG=$(echo "$MONITOR_OUTPUT" | grep "Backlog:" | grep -o '[0-9.]*%' | tr -d '%')
    if (( $(echo "$BACKLOG > $ALERT_THRESHOLD" | bc -l) )); then
        echo "⚠️  HIGH BACKLOG ALERT: $BACKLOG%" >> $LOG_FILE
        echo "$(date): HIGH BACKLOG $BACKLOG%" >> logs/alerts.log
    fi
    
    # Check for process failures
    if echo "$MONITOR_OUTPUT" | grep -q "❌ DOWN"; then
        echo "⚠️  PROCESS DOWN ALERT" >> $LOG_FILE
        echo "$(date): PROCESS FAILURE" >> logs/alerts.log
    fi
    
    echo "" >> $LOG_FILE
    sleep 300  # Wait 5 minutes
done
