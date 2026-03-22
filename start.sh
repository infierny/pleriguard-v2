#!/bin/bash
# start.sh - Launcher for Pleriguard V2
# Usage: ./start.sh [collector|intel|classifier|dashboard|all]

set -e
cd ~/.openclaw/workspace/pleriguard/v2-stage
VENV="$HOME/.openclaw/workspace/pleriguard/v2/venv"

source "$VENV/bin/activate"
export PYTHONPATH="$PWD:$PYTHONPATH"

case "${1:-all}" in
  collector)
    echo "🚀 Starting V2 Collector..."
    python collectors/collector.py --loop
    ;;
  intel)
    echo "📡 Starting V2 Intel Collector..."
    python collectors/intel_collector.py --loop
    ;;
  classifier)
    echo "🎯 Starting V2 Classifier..."
    python classification/classifier.py --loop
    ;;
  dashboard)
    echo "📊 Starting V2 Dashboard on http://localhost:5010..."
    python dashboard.py
    ;;
  all)
    echo "🚀 Starting V2 Pipeline (all components)..."
    python collectors/collector.py --loop &
    sleep 2
    python collectors/intel_collector.py --loop &
    sleep 2
    python classification/classifier.py --loop &
    python dashboard.py
    ;;
  *)
    echo "Usage: $0 [collector|intel|classifier|dashboard|all]"
    exit 1
    ;;
esac
