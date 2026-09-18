#!/bin/bash
#
# Script to analyze chunk files sequentially and save outputs
#

VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -verbose)
            VERBOSE=true
            shift
            ;;
        *)
            CHUNKS_DIR="$1"
            shift
            ;;
    esac
done

if [ -z "$CHUNKS_DIR" ]; then
    echo "Usage: $0 <chunks_directory> [-verbose]"
    echo "Example: $0 ./chunks"
    echo "         $0 ./chunks -verbose"
    exit 1
fi
OUTPUT_DIR="./chunk_outputs"

if [ ! -d "$CHUNKS_DIR" ]; then
    echo "Error: Directory '$CHUNKS_DIR' not found."
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Get all chunk files sorted numerically (1, 2, 3, ... 10, 11, ...)
chunk_files=$(ls -1 "$CHUNKS_DIR"/chunk*.rules 2>/dev/null | sort -V)

if [ -z "$chunk_files" ]; then
    echo "No chunk files found in $CHUNKS_DIR"
    exit 1
fi

echo "Found chunk files to process:"
echo "$chunk_files"
echo ""

for chunk_file in $chunk_files; do
    # Extract chunk number/name for output file
    chunk_name=$(basename "$chunk_file" .rules)
    output_file="$OUTPUT_DIR/${chunk_name}_output.json"

    if [ -f "$output_file" ]; then
        echo "$output_file already exists. Checking the current FailedRuleSids count."
        output_contents=$(cat "$output_file")
        failed_rule_sids=$(echo "$output_contents" | jq -r '.result.RuleAnalysisResult.ReportMetadata.FailedRuleSids // []')
        failed_count=$(echo "$failed_rule_sids" | jq 'length')

        # Filter bad performing rules from original chunk file only if FailedRuleSids is not empty
        if [ "$failed_count" -eq 0 ]; then
            echo "Skipping the processing of $chunk_file as failed count is $failed_count."
            continue
        fi
    fi

    echo "============================================================"
    echo "Processing: $chunk_file"
    echo "Output: $output_file"
    echo "============================================================"
        
    # Retry loop for analyzing and filtering bad rules
    retry=true
    while $retry; do
        retry=false

        # Filter the rules file first
        echo "Filtering rules: $chunk_file"
        python3 ./scripts/filter_rules.py "$chunk_file"
        
        # Run command and capture output
        if [ "$VERBOSE" = true ]; then
            full_output=$(poetry run python3 ./scripts/create_rule_group_minimal.py \
                --name EmproviseBlockStrictOrder \
                --order STRICT_ORDER \
                --rules "$chunk_file" \
                --region us-east-1 \
                --wait 300 \
                2>&1 | tee /dev/tty)
        else
            full_output=$(poetry run python3 ./scripts/create_rule_group_minimal.py \
                --name EmproviseBlockStrictOrder \
                --order STRICT_ORDER \
                --rules "$chunk_file" \
                --region us-east-1 \
                --wait 300 \
                2>&1)
        fi
        
        # Check for InvalidRequestException error
        error_marker="us-east-1:analyse-file: error"

        if echo "$full_output" | grep -q "us-east-1:analyse-file: error"; then
            processed_output=$(echo "$full_output" | sed -n "/${error_marker}/,\$p" | sed "1s/.*${error_marker}//" | sed '/^[[:space:]]*$/d' | sed 's/^[[:space:]]*//')
            echo ""
            echo "============================================================"
            echo "ERROR: detected for $chunk_file"
            echo "$processed_output"| jq .
            echo "Terminating script."
            echo "============================================================"
            exit 1
        fi
        
        # Save only content after the marker string, removing leading whitespace/newlines
        completed_marker="us-east-1:analyse-file: completed"
        processed_output=$(echo "$full_output" | sed -n "/${completed_marker}/,\$p" | sed "1s/.*${completed_marker}//" | sed '/^[[:space:]]*$/d' | sed 's/^[[:space:]]*//')
        
        # Only create output file if there's content
        if [ -n "$processed_output" ]; then
            rm -f "$output_file"
            echo "$processed_output" > "$output_file"
            echo -e "\n\nOutput saved to: $output_file"

            # Extract FailedRuleSids array from JSON
            failed_rule_sids=$(echo "$processed_output" | jq -r '.result.RuleAnalysisResult.ReportMetadata.FailedRuleSids // []')
            failed_count=$(echo "$failed_rule_sids" | jq 'length')

            # Filter bad performing rules from original chunk file only if FailedRuleSids is not empty
            if [ "$failed_count" -gt 0 ]; then
                echo "Found $failed_count failed rule SIDs, filtering bad performing rules in $chunk_file"
                python3 ./scripts/extract_bad_rules.py "$chunk_file" "$output_file"
                echo "Successfully filtering bad performing rules in $chunk_file"
                
                # Retry analysis after filtering bad performing rules
                echo "Retrying analysis after filtering bad performing rules..."
                retry=true
            else
                echo "No failed rule SIDs found, skipping filtering"
            fi
        else
            echo "No output after marker, skipping file creation"
        fi
    done
    
    echo ""
    echo "Completed: $chunk_file"
    echo ""
done

echo "============================================================"
echo "All chunks processed. Outputs saved in $OUTPUT_DIR"
echo "============================================================"
