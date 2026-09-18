#!/bin/bash

# --- PERFORMANCE STANDARDS (Adjust as needed) ---
# Ticks represent CPU cycles; lower is more efficient.
MAX_AVG_TICKS=2000   # Rules above this are considered "Slow"
MAX_PEAK_TICKS=15000  # Rules with single spikes above this "Fail"

# --- INPUTS ---
RULES_FILE=$1
PCAP_FILE=$2
OUTPUT_DIR="$(pwd)/perf_results"

if [[ ! -f "$RULES_FILE" || ! -f "$PCAP_FILE" ]]; then
    echo "Usage: ./performance_check.sh <rules_file> <pcap_file>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
chmod -R 777 "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR/rule_perf.log"

echo "[*] Building Suricata with profiling (this may take a few minutes)..."
docker build -t suricata-profiler . -q

echo "[*] Running performance analysis..."
docker run --rm \
    -v "$(realpath $RULES_FILE)":/tmp/test.rules \
    -v "$(realpath $PCAP_FILE)":/tmp/test.pcap \
    -v "$OUTPUT_DIR":/var/log/suricata \
    suricata-profiler \
    -v \
    -c /etc/suricata/suricata.yaml \
    -l /var/log/suricata \
    -S /tmp/test.rules \
    -r /tmp/test.pcap \
    --set logging.outputs.0.console.enabled=yes \
    --set profiling.rules.enabled=yes \
    --set profiling.rules.filename=rule_perf.log \
    --set profiling.rules.sort=avgticks \
    --set profiling.rules.append=no

# --- ANALYSIS ENGINE ---
echo "[*] Files generated in output directory:"
ls -l "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/rule_perf.log"

if [[ ! -f "$LOG" ]]; then
    # Final check: Did Suricata name it differently?
    GEN_LOG=$(find "$OUTPUT_DIR" -name "rule_perf.log*")
    if [[ -n "$GEN_LOG" ]]; then
        LOG=$GEN_LOG
    else
        echo "Error: Profiling log not generated."
        exit 1
    fi
fi

echo -e "\nDetailed Rule Performance Report:"
echo "------------------------------------------------------------------------------------"
printf "%-10s | %-12s | %-12s | %-10s | %-8s\n" "SID" "Avg Ticks" "Max Ticks" "Checks" "Result"
echo "------------------------------------------------------------------------------------"

# Parse the log file (skipping headers and selecting data columns)
awk -v avg_limit="$MAX_AVG_TICKS" -v max_limit="$MAX_PEAK_TICKS" '
    /^[0-9]/ {
        sid=$1; ticks=$4; checks=$6; max_t=$8; avg_t=$9;
        
        status = "GOOD"
        if (avg_t > avg_limit || max_t > max_limit) { status = "SLOW" }
        if (checks == 0) { status = "SKIPPED" }

        printf "%-10s | %-12.2f | %-12d | %-10d | %-8s\n", sid, avg_t, max_t, checks, status
    }
' "$LOG"