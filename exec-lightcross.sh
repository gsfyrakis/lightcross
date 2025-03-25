#!/bin/bash

# List of folders
folders=(
  "bad_randomness"
  "denial_of_service"
  "front_running"
  "other"
  # "reentrancy"
  # "short_addresses"
  # "time_manipulation"
  # "unchecked_low_level_calls"
)

# Iterate over each folder
for folder in "${folders[@]}"
do
  echo "Processing folder: $folder"
  
  # Execute the Python script with the folder as a parameter
  python3 smartvulscan.py "smartbugs-dataset/$folder"
  
  # Check if output.csv exists
  if [ -f "output.csv" ]; then
    # Copy output.csv to folder.csv
    cp "output.csv" "$folder.csv"
    echo "Copied output.csv to $folder.csv"
  else
    echo "output.csv not found for $folder"
  fi
  
  echo "Finished processing folder: $folder"
  echo "---"
done
