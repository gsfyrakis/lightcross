#!/usr/bin/env python
"""
Script to run the OpenScv Smart Contract Vulnerability Mapper
"""

import argparse
import sys
import os
import glob
from vulnerability_mapper import OpenScvVulnerabilityMapper


def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(
        description='Map smart contract vulnerabilities from multiple output files to openscvfull.csv'
    )

    parser.add_argument(
        '--input',
        type=str,
        nargs='+',
        help='Path(s) to the vulnerability CSV files. Can be file paths or glob patterns (e.g., output_*.csv)'
    )

    parser.add_argument(
        '--openscv',
        type=str,
        default='openscvfull.csv',
        help='Path to the openscvfull.csv file (default: openscvfull.csv)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default='outputs',
        help='Directory to save the output files (default: outputs)'
    )

    parser.add_argument(
        '--csv',
        action='store_true',
        help='Export results to CSV (default: enabled)'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Export results to JSON (default: enabled)'
    )

    parser.add_argument(
        '--visualize',
        action='store_true',
        help='Generate visualizations (default: enabled)'
    )

    args = parser.parse_args()

    # If no input files specified, use a default pattern
    if not args.input:
        args.input = ['output_*.csv']

    # If no export format is specified, enable both by default
    if not args.csv and not args.json:
        args.csv = True
        args.json = True

    # Enable visualization by default
    if not args.visualize:
        args.visualize = True

    return args


def expand_input_files(input_patterns):
    """
    Expand glob patterns in input files list.

    Args:
        input_patterns: List of file paths or glob patterns

    Returns:
        List of expanded file paths
    """
    expanded_files = []

    for pattern in input_patterns:
        if '*' in pattern or '?' in pattern:
            # This is a glob pattern
            matching_files = glob.glob(pattern)
            if not matching_files:
                print(f"Warning: No files found matching pattern '{pattern}'")
            expanded_files.extend(matching_files)
        else:
            # This is a single file
            expanded_files.append(pattern)

    return expanded_files


def main():
    """
    Main function to run the OpenScv vulnerability mapper
    """
    args = parse_args()

    input_files = expand_input_files(args.input)

    if not input_files:
        print("Error: No input files specified or found")
        sys.exit(1)

    if not os.path.exists(args.openscv):
        print(f"Error: OpenSCV file not found - {args.openscv}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Initializing OpenSCV mapper with:")
    print(f"  - {len(input_files)} input file(s)")
    for f in input_files:
        print(f"    - {f}")
    print(f"  - OpenSCV file: {args.openscv}")

    try:
        mapper = OpenScvVulnerabilityMapper(input_files, args.openscv)

        if args.csv:
            csv_path = os.path.join(args.output_dir, 'openscv_vulnerability_mapping.csv')
            print(f"Exporting mapping results to CSV: {csv_path}")
            mapper.export_mapping(csv_path)

        if args.json:
            json_path = os.path.join(args.output_dir, 'openscv_vulnerability_mapping.json')
            print(f"Exporting mapping results to JSON: {json_path}")
            mapper.export_json_mapping(json_path)

        vis_dir = os.path.join(args.output_dir, 'visualizations') if args.visualize else None
        print("Generating statistics...")
        statistics = mapper.generate_statistics(vis_dir)

        print("\nMapping Summary:")
        print(f"Total vulnerabilities: {statistics['match_stats']['total']}")
        print(f"Mapped by SWC-ID: {statistics['mapping_method']['swc_id']}")
        print(f"Mapped by keyword: {statistics['mapping_method']['keyword']}")
        print(f"Unmapped: {statistics['mapping_method']['unmapped']}")
        print(f"Match rate: {statistics['match_stats']['match_rate']}%")

        print("\nVulnerability Categories:")
        for category, count in sorted(statistics['category_counts'].items(), key=lambda x: x[1], reverse=True):
            print(f"  - {category}: {count} vulnerabilities")
            if category in statistics['mapping_by_category']:
                cat_stats = statistics['mapping_by_category'][category]
                print(f"    Match rate: {cat_stats['match_rate']}%")

        print("\nTop 5 SWC-IDs:")
        # Print top 5 SWC-IDs
        sorted_swcs = sorted(statistics['swc_counts'].items(), key=lambda x: x[1], reverse=True)
        for i, (swc_id, count) in enumerate(sorted_swcs[:5], 1):
            print(f"{i}. {swc_id}: {count} occurrences")

        if args.visualize:
            print(f"\nVisualizations saved to: {vis_dir}")

        print("\nMapping completed successfully!")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()