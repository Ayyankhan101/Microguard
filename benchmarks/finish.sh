#!/usr/bin/env bash
# Waits for the ladder matrix to finish, then runs the whole analysis pipeline:
# score the ladder, the model track, the performance suite, and render the
# report. One completion marker at the end. Safe to run while the matrix is
# still going -- it blocks until the matrix log says it is done.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
LOG=/tmp/matrix.log
MARK=/tmp/finish.done
rm -f "$MARK"

echo "[finish] waiting for the matrix to complete..."
while true; do
  grep -q "all cells done" "$LOG" 2>/dev/null && break
  grep -qE "Traceback|nginx exited|serve exited" "$LOG" 2>/dev/null && { echo "[finish] matrix errored; running analysis on whatever completed"; break; }
  sleep 30
done

echo "[finish] === scoring the ladder ==="
python -m benchmarks.ladder.score 2>&1 | tail -3

echo "[finish] === model track ==="
python -m benchmarks.model.track 2>&1 | tail -8

echo "[finish] === performance suite ==="
python -m benchmarks.perf.latency 2>&1 | tail -20

echo "[finish] === rendering the report ==="
python -m benchmarks.report 2>&1 | tail -2

echo "[finish] === LinkedIn card ==="
python -m benchmarks.linkedin 2>&1 | tail -5

echo "DONE" > "$MARK"
echo "[finish] all analysis complete -> $MARK"
