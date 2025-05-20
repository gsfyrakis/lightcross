#!/bin/bash

TOOLS="both"

function show_usage {
  echo "Usage: $0 [OPTIONS]"
  echo "Options:"
  echo "  -t, --tools TOOL    Specify which tools to run: slither, mythril, or both (default)"
  echo "  -h, --help          Show this help message and exit"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tools)
      TOOLS="$2"
      # Validate tool selection
      if [[ ! "$TOOLS" =~ ^(slither|mythril|both)$ ]]; then
        echo "Error: Invalid tool selection. Must be 'slither', 'mythril', or 'both'."
        show_usage
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      show_usage
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1"
      show_usage
      exit 1
      ;;
  esac
done

echo "Running analysis with tool(s): $TOOLS"

folders=(
   "access_control"
   "bad_randomness"
   "denial_of_service"
   "front_running"
   "other"
   "reentrancy"
   "short_addresses"
   "time_manipulation"
   "unchecked_low_level_calls"
)

for folder in "${folders[@]}"
do
  echo "Processing folder: $folder"

  python3 smartvulscan.py "smartbugs-dataset/$folder" --tools "$TOOLS"

  if [ -f "output.csv" ]; then
    if [ "$TOOLS" == "both" ]; then
      output_filename="${folder}.csv"
    else
      output_filename="${folder}_${TOOLS}.csv"
    fi

    cp "output.csv" "$output_filename"
    echo "Copied output.csv to $output_filename"
  else
    echo "output.csv not found for $folder"
  fi

  echo "Finished processing folder: $folder"
  echo "---"
done

echo "Analysis complete!"