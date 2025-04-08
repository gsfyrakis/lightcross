#!/usr/bin/env python3
"""
Run the complete vulnerability detection analysis, including VD-Score metrics.

This script runs both the tool/contract breakdown analysis and the Excel report generation.

Usage:
    python run_analysis.py [--ground-truth GROUND_TRUTH] [--output-dir OUTPUT_DIR]
"""

import os
import sys
import argparse

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run vulnerability detection analysis')
    
    parser.add_argument('--ground-truth', type=str, default='sb_vulnerabilities_dasp.csv',
                        help='Path to the ground truth CSV file (default: sb_vulnerabilities_dasp.csv)')
    
    parser.add_argument('--output-dir', type=str, default='.',
                        help='Directory containing output CSV files (default: current directory)')
    
    parser.add_argument('--report-file', type=str, default='vulnerability_report.txt',
                        help='Path to save the report (default: vulnerability_report.txt)')
    
    parser.add_argument('--export-dir', type=str, default='results',
                        help='Directory to save exported CSV files (default: results)')
    
    parser.add_argument('--vd-score-tolerance', type=float, default=0.005,
                        help='FPR tolerance for VD-Score (default: 0.005 or 0.5%)')
    
    return parser.parse_args()

def main():
    """Main function to run the analysis."""
    args = parse_args()
    
    # Ensure the vd_score_calculator module is available
    try:
        from vd_score_calculator import calculate_vd_score
    except ImportError:
        print("Error: vd_score_calculator module not found. Please make sure it's in the current directory.")
        sys.exit(1)
    
    # Check if ground truth file exists
    if not os.path.isfile(args.ground_truth):
        print(f"Error: Ground truth file '{args.ground_truth}' not found.")
        sys.exit(1)
    
    # Find output files
    output_files = [
        os.path.join(args.output_dir, 'output_access_control.csv'),
        os.path.join(args.output_dir, 'output_arithmetic.csv'),
        os.path.join(args.output_dir, 'output_bad_randomness.csv'),
        os.path.join(args.output_dir, 'output_denial_of_service.csv'),
        os.path.join(args.output_dir, 'output_front_running.csv'),
        os.path.join(args.output_dir, 'output_other.csv'),
        os.path.join(args.output_dir, 'output_reentrancy.csv'),
        os.path.join(args.output_dir, 'output_short_addresses.csv'),
        os.path.join(args.output_dir, 'output_time_manipulation.csv'),
        os.path.join(args.output_dir, 'output_unchecked_low_level_calls.csv')
    ]
    
    # Filter for existing files
    existing_files = [f for f in output_files if os.path.isfile(f)]
    
    if not existing_files:
        print(f"Error: No output CSV files found in directory '{args.output_dir}'")
        sys.exit(1)
    
    print(f"Found {len(existing_files)} output files")
    
    # Run tool and contract breakdown analysis
    print("\nRunning tool and contract breakdown analysis...")
    from tool_contract_breakdown import (
        load_ground_truth,
        analyze_by_tool,
        analyze_by_contract,
        calculate_false_negatives,
        generate_tool_breakdown_report,
        generate_contract_breakdown_report,
        visualize_tool_performance,
        visualize_category_performance
    )
    
    # Load ground truth
    ground_truth_data = load_ground_truth(args.ground_truth)
    print(f"Loaded {len(ground_truth_data)} entries from ground truth")
    
    # Run analysis
    tool_results = analyze_by_tool(existing_files, ground_truth_data)
    contract_results = analyze_by_contract(existing_files, ground_truth_data)
    tool_results, contract_results = calculate_false_negatives(tool_results, contract_results, ground_truth_data)
    
    # Generate text report
    print("\nGenerating text report...")
    with open(args.report_file, 'w') as f:
        # Redirect stdout to file
        original_stdout = sys.stdout
        sys.stdout = f
        
        print(f"VD-Score Analysis with FPR tolerance: {args.vd_score_tolerance:.4f}")
        print("=" * 80)
        
        generate_tool_breakdown_report(tool_results)
        generate_contract_breakdown_report(contract_results)
        
        # Restore stdout
        sys.stdout = original_stdout
    
    print(f"Report saved to {args.report_file}")
    
    # Generate visualizations
    print("\nGenerating visualizations...")
    visualize_tool_performance(tool_results)
    visualize_category_performance(tool_results, contract_results)
    
    # Generate CSV report
    print("\nExporting results to CSV files...")
    try:
        from csv_exporter import (
            export_tool_results,
            export_contract_results,
            export_category_results,
            export_tool_category_matrix,
            export_summary
        )
        
        # Create export directory if it doesn't exist
        export_dir = args.export_dir
        os.makedirs(export_dir, exist_ok=True)
        
        # Export results to CSV files
        export_tool_results(tool_results, os.path.join(export_dir, 'tool_results.csv'))
        export_contract_results(contract_results, os.path.join(export_dir, 'contract_results.csv'))
        export_category_results(contract_results, os.path.join(export_dir, 'category_results.csv'), args.vd_score_tolerance)
        export_tool_category_matrix(tool_results, contract_results, os.path.join(export_dir, 'tool_category_matrix.csv'), args.vd_score_tolerance)
        export_summary(tool_results, contract_results, os.path.join(export_dir, 'summary.csv'))
        
        print("\nAll results exported to CSV files in:", export_dir)
    except ImportError:
        print("Warning: csv_exporter module not found. CSV export not performed.")
    
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()
