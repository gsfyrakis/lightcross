#!/usr/bin/env python3
"""
Script to run Smart Contract Vulnerability Analysis
"""
from vulnerability_metrics import VulnerabilityAnalyzer

def main():
    print("Starting Smart Contract Vulnerability Analysis...")
    analyzer = VulnerabilityAnalyzer()
    analyzer.analyze_vulnerabilities()
    
    print("\nMetrics Results:")
    analyzer.print_results()
    
    analyzer.export_results('vulnerability_metrics_results.csv')
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()
