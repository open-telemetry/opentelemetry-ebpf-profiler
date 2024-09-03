#!/usr/bin/env bash

# Script to append legal information for non Go dependencies.

set -eu
set -o pipefail

# Set the input file to the first argument or default to foobar.json
input_file="${1:-non-go-dependencies.json}"

# Set the prefix directory to the second argument or default to current directory
prefix_dir="${2:-.}"

# Ensure prefix_dir ends with a slash
prefix_dir="${prefix_dir%/}/"


# Check if the file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found."
    exit 1
fi

# Function to process each dependency
process_dependency() {
    local dep="$1"
    
    # Extract values from JSON using jq
    dependency=$(echo "$dep" | jq -r '.Dependency')
    licence_file=$(echo "$dep" | jq -r '.LicenceFile')

    # Create directory structure
    dir_structure="./${prefix_dir}${dependency}"
    mkdir -p "$dir_structure"

    # Extract the filename from the LicenceFile URL
    filename=$(basename "$licence_file")

    # Download the license file
    wget -q -O "$dir_structure/$filename" "$licence_file"

    if [ $? -eq 0 ]; then
        echo "License file for $dependency downloaded successfully to $dir_structure/$filename"
    else
        echo "Failed to download license file for $dependency"
    fi
}

# Read and process the JSON file
jq -c '.[]' "$input_file" | while read -r dep; do
    process_dependency "$dep"
done