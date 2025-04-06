#!/usr/bin/env python3
"""
Complete Smart Contract Vulnerability Analysis Pipeline

This script:
1. Analyzes vulnerability detection results from various tools
2. Calculates TP, FP, FN, precision, and recall metrics
3. Generates visualizations of the results
"""
import os
import argparse


from vulnerability_metrics import VulnerabilityAnalyzer
from visualize_results import plot_metrics

def parse_args():
    parser = argparse.ArgumentParser(description='Smart Contract Vulnerability Analysis Pipeline')
    parser.add_argument('--data-dir', type=str, default='.',
                        help='Directory containing the output_*.csv files')
    parser.add_argument('--mapping-file', type=str, default='sb_vulnerabilities_dasp.csv',
                        help='Path to the vulnerability mapping file')
    parser.add_argument('--results-file', type=str, default='vulnerability_metrics_results.csv',
                        help='File name for the results CSV')
    parser.add_argument('--plots-dir', type=str, default='plots',
                        help='Directory to save visualization plots')
    parser.add_argument('--skip-plots', action='store_true',
                        help='Skip generating plots')
    return parser.parse_args()

def main():
    # Parse command line arguments
    args = parse_args()
    
    print("=" * 80)
    print("SMART CONTRACT VULNERABILITY ANALYSIS PIPELINE")
    print("=" * 80)
    
    # Step 1: Run the vulnerability analysis
    print("\n[1/3] Analyzing vulnerability detection results...")
    analyzer = VulnerabilityAnalyzer(args.data_dir, args.mapping_file)
    analyzer.analyze_vulnerabilities()
    
    # Step 2: Export the results
    print("\n[2/3] Exporting analysis results...")
    analyzer.export_results(args.results_file)
    
    # Step 3: Display the results
    print("\n[3/3] Analysis results summary:")
    print("-" * 80)
    analyzer.print_results()
    print("-" * 80)
    
    # Step 4: Generate visualizations (if not skipped)
    if not args.skip_plots:
        print("\nGenerating visualizations...")
        plot_metrics(args.results_file, args.plots_dir)
        print(f"Plots saved to '{args.plots_dir}' directory")
    
    print("\nAnalysis pipeline completed successfully!")
    print(f"Results saved to: {args.results_file}")

if __name__ == "__main__":
    main()
