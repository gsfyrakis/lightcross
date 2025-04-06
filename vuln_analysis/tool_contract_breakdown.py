#!/usr/bin/env python3
"""

This script analyzes vulnerability detection results by Mythril and Slither and by smart contract file.

Usage:
    python tool_contract_breakdown.py
"""

import csv
import os
import re
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from vulnerability_metrics import extract_swc_id, extract_filename, determine_dasp_category

from vd_score_calculator import calculate_vd_score

def load_ground_truth(ground_truth_file):
    """
    Load the ground truth data from CSV file.
    
    Args:
        ground_truth_file: Path to the ground truth CSV file
        
    Returns:
        Dictionary mapping filenames to their vulnerability info
    """
    ground_truth = {}
    
    with open(ground_truth_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'path' in row and row['path']:
                path = row['path']
                filename = extract_filename(path)
                
                ground_truth[path] = {
                    'dasp': row['dasp'],
                    'category': row['category'],
                    'vulnerable_lines': row.get('vulnerable_lines', '')
                }
                
                if filename:
                    ground_truth[filename] = {
                        'dasp': row['dasp'],
                        'category': row['category'],
                        'vulnerable_lines': row.get('vulnerable_lines', '')
                    }
    
    return ground_truth


def analyze_by_tool(output_files, ground_truth_data):
    """
    Analyze vulnerability detection results broken down by tool.
    
    Args:
        output_files: List of output CSV files
        ground_truth_data: Dictionary of ground truth data
        
    Returns:
        Dictionary containing the analysis by tool
    """
    tool_results = defaultdict(lambda: {
        'true_positives': 0,
        'false_positives': 0,
        'files_analyzed': set(),
        'by_category': defaultdict(lambda: {
            'true_positives': 0,
            'false_positives': 0
        })
    })
    
    for output_file in output_files:
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'Tool' not in row or 'File' not in row:
                    continue
                
                tool = row['Tool']
                file_path = row['File']
                filename = extract_filename(file_path)
                
                if not tool or not file_path:
                    continue
                
                tool_results[tool]['files_analyzed'].add(file_path)
                print("Analyzed contract entry in dataset: " + file_path)
                
                swc_id = extract_swc_id(row.get('SWC-ID', ''))
                vulnerability = row.get('Vulnerability', '')
                detected_category = determine_dasp_category(swc_id, vulnerability)
                
                ground_truth = (ground_truth_data.get(file_path) or
                               ground_truth_data.get(filename))
                
                if ground_truth:
                    if ground_truth['dasp'] == detected_category:
                        tool_results[tool]['true_positives'] += 1
                        tool_results[tool]['by_category'][detected_category]['true_positives'] += 1
                    else:
                        tool_results[tool]['false_positives'] += 1
                        tool_results[tool]['by_category'][detected_category]['false_positives'] += 1
                else:
                    tool_results[tool]['false_positives'] += 1
                    tool_results[tool]['by_category'][detected_category]['false_positives'] += 1
    
    for tool, results in tool_results.items():
        tp = results['true_positives']
        fp = results['false_positives']
        
        results['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
        results['files_analyzed_count'] = len(results['files_analyzed'])
        
        for category, cat_results in results['by_category'].items():
            cat_tp = cat_results['true_positives']
            cat_fp = cat_results['false_positives']
            cat_results['precision'] = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
    
    return tool_results


def analyze_by_contract(output_files, ground_truth_data):
    """
    Analyze vulnerability detection results broken down by smart contract file.
    
    Args:
        output_files: List of output CSV files
        ground_truth_data: Dictionary of ground truth data
        
    Returns:
        Dictionary containing the analysis by contract
    """
    contract_results = defaultdict(lambda: {
        'true_positives': 0,
        'false_positives': 0,
        'tools_detected': set(),
        'by_tool': defaultdict(lambda: {
            'true_positives': 0,
            'false_positives': 0
        }),
        'ground_truth_category': None
    })
    
    for output_file in output_files:
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'Tool' not in row or 'File' not in row:
                    continue
                
                tool = row['Tool']
                file_path = row['File']
                filename = extract_filename(file_path)
                
                if not tool or not file_path:
                    continue
                
                contract_results[file_path]['tools_detected'].add(tool)
                
                swc_id = extract_swc_id(row.get('SWC-ID', ''))
                vulnerability = row.get('Vulnerability', '')
                detected_category = determine_dasp_category(swc_id, vulnerability)
                
                ground_truth = (ground_truth_data.get(file_path) or
                               ground_truth_data.get(filename))
                
                if ground_truth:
                    contract_results[file_path]['ground_truth_category'] = ground_truth['dasp']
                
                if ground_truth:
                    if ground_truth['dasp'] == detected_category:
                        contract_results[file_path]['true_positives'] += 1
                        contract_results[file_path]['by_tool'][tool]['true_positives'] += 1
                    else:
                        contract_results[file_path]['false_positives'] += 1
                        contract_results[file_path]['by_tool'][tool]['false_positives'] += 1
                else:
                    contract_results[file_path]['false_positives'] += 1
                    contract_results[file_path]['by_tool'][tool]['false_positives'] += 1
    
    for file_path, results in contract_results.items():
        tp = results['true_positives']
        fp = results['false_positives']
        
        results['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
        results['tools_detected_count'] = len(results['tools_detected'])
        
        for tool, tool_results in results['by_tool'].items():
            tool_tp = tool_results['true_positives']
            tool_fp = tool_results['false_positives']
            tool_results['precision'] = tool_tp / (tool_tp + tool_fp) if (tool_tp + tool_fp) > 0 else 0
    
    return contract_results


def calculate_false_negatives(tool_results, contract_results, ground_truth_data):
    """
    Calculate false negatives for each tool and contract.
    
    Args:
        tool_results: Dictionary of tool analysis results
        contract_results: Dictionary of contract analysis results
        ground_truth_data: Dictionary of ground truth data
        
    Returns:
        Updated tool_results and contract_results with false negatives added
    """
    all_tools = set(tool_results.keys())
    
    ground_truth_files = set(ground_truth_data.keys())
    
    for tool in all_tools:
        tool_results[tool]['false_negatives'] = 0
        tool_results[tool]['by_category_false_negatives'] = defaultdict(int)
        
        files_analyzed = tool_results[tool]['files_analyzed']
        
        for file_path, ground_truth in ground_truth_data.items():
            if '/' not in file_path:
                continue
                
            dasp_category = ground_truth['dasp']
            
            file_detected = False
            for analyzed_file in files_analyzed:
                if file_path in analyzed_file or extract_filename(file_path) == extract_filename(analyzed_file):
                    file_detected = True
                    file_in_results = False
                    for result_file, results in contract_results.items():
                        if file_path in result_file or extract_filename(file_path) == extract_filename(result_file):
                            if results['by_tool'].get(tool, {}).get('true_positives', 0) > 0:
                                file_in_results = True
                                break
                    
                    if not file_in_results:
                        tool_results[tool]['false_negatives'] += 1
                        tool_results[tool]['by_category_false_negatives'][dasp_category] += 1
                        
                    break
            
            if not file_detected:
                tool_results[tool]['false_negatives'] += 1
                tool_results[tool]['by_category_false_negatives'][dasp_category] += 1
    
    for tool, results in tool_results.items():
        tp = results['true_positives']
        fp = results['false_positives']
        fn = results['false_negatives']
        tn = sum(len(ground_truth_data.get(file, {})) > 0 for file in ground_truth_files) - tp - fp - fn
        
        y_true = []
        y_pred_prob = []
        
        for file_path in ground_truth_files:
            if '/' not in file_path:
                continue
                
            is_vulnerable = True
            
            file_detected = False
            prob_value = 0.0
            
            for analyzed_file in results['files_analyzed']:
                if file_path in analyzed_file or extract_filename(file_path) == extract_filename(analyzed_file):
                    for result_file, file_results in contract_results.items():
                        if (file_path in result_file or extract_filename(file_path) == extract_filename(result_file)) and \
                           tool in file_results['by_tool']:
                            correct_detection = file_results['by_tool'][tool]['true_positives'] > 0
                            file_detected = True
                            prob_value = 1.0 if correct_detection else 0.5
                            break
                    
                    if file_detected:
                        break
            
            y_true.append(1 if is_vulnerable else 0)
            y_pred_prob.append(prob_value)
        
        for file_path, file_results in contract_results.items():
            if file_path not in ground_truth_files and '/' in file_path:
                if tool in file_results['by_tool']:
                    false_positive = file_results['by_tool'][tool]['false_positives'] > 0
                    y_true.append(0)  # 0 for benign
                    y_pred_prob.append(0.8 if false_positive else 0.2)
        
        # Calculate VD-Score if we have enough data
        if len(y_true) > 0 and len(y_pred_prob) > 0:
            vd_score_result = calculate_vd_score(y_true, y_pred_prob, tolerance=0.005)
            results['vd_score'] = vd_score_result['vd_score']
            results['vd_score_threshold'] = vd_score_result['threshold']
            results['vd_score_fpr'] = vd_score_result['fpr']
        else:
            results['vd_score'] = 1.0  # Default to worst score if no data
            results['vd_score_threshold'] = 0.0
            results['vd_score_fpr'] = 0.0
        
        results['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
        results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall']) if (results['precision'] + results['recall']) > 0 else 0
    
    for file_path, ground_truth in ground_truth_data.items():
        if '/' not in file_path:
            continue
            
        if file_path not in contract_results:
            contract_results[file_path] = {
                'true_positives': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'tools_detected': set(),
                'by_tool': {},
                'ground_truth_category': ground_truth['dasp']
            }
        else:
            contract_results[file_path]['false_negatives'] = 0
        
        for tool in all_tools:
            tool_detected_correctly = False
            
            if tool in contract_results[file_path]['by_tool']:
                if contract_results[file_path]['by_tool'][tool]['true_positives'] > 0:
                    tool_detected_correctly = True
            
            if not tool_detected_correctly:
                contract_results[file_path]['false_negatives'] += 1
    
    for file_path, results in contract_results.items():
        tp = results['true_positives']
        fn = results.get('false_negatives', 0)
        
        results['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
        results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall']) if (results.get('precision',0) + results['recall']) > 0 else 0
    
    return tool_results, contract_results


def generate_tool_breakdown_report(tool_results):
    """
    Generate a detailed report of the performance breakdown by tool.
    
    Args:
        tool_results: Dictionary containing the analysis by tool
    """
    print("\n" + "="*80)
    print(" "*20 + "VULNERABILITY DETECTION PERFORMANCE BY TOOL")
    print("="*80)
    
    sorted_tools = sorted(
        tool_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )
    
    print("\n{:<15} {:<8} {:<8} {:<8} {:<10} {:<10} {:<10} {:<10}".format(
        "Tool", "TP", "FP", "FN", "Precision", "Recall", "F1 Score", "VD-S"))
    print("-"*80)
    
    for tool, results in sorted_tools:
        print("{:<15} {:<8} {:<8} {:<8} {:<10.4f} {:<10.4f} {:<10.4f} {:<10.4f}".format(
            tool,
            results['true_positives'],
            results['false_positives'],
            results.get('false_negatives', 0),
            results.get('precision', 0),
            results.get('recall', 0),
            results.get('f1_score', 0),
            results.get('vd_score', 1.0)
        ))
    
    for tool, results in sorted_tools:
        print("\n" + "-"*40)
        print(f"Detailed Analysis for Tool: {tool}")
        print("-"*40)
        
        print(f"Files Analyzed: {results['files_analyzed_count']}")
        print(f"True Positives: {results['true_positives']}")
        print(f"False Positives: {results['false_positives']}")
        print(f"False Negatives: {results.get('false_negatives', 0)}")
        print(f"Precision: {results.get('precision', 0):.4f}")
        print(f"Recall: {results.get('recall', 0):.4f}")
        print(f"F1 Score: {results.get('f1_score', 0):.4f}")
        print(f"VD-Score (FNR @ FPR ≤ 0.5%): {results.get('vd_score', 1.0):.4f}")
        print(f"VD-Score Threshold: {results.get('vd_score_threshold', 0.0):.4f}")
        print(f"VD-Score FPR: {results.get('vd_score_fpr', 0.0):.4f}")
        
        print("\nPerformance by Category:")
        
        categories = set(results['by_category'].keys())
        if 'by_category_false_negatives' in results:
            categories.update(results['by_category_false_negatives'].keys())
        
        for category in sorted(categories):
            cat_results = results['by_category'].get(category, {})
            cat_tp = cat_results.get('true_positives', 0)
            cat_fp = cat_results.get('false_positives', 0)
            cat_fn = results.get('by_category_false_negatives', {}).get(category, 0)
            
            cat_precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
            cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
            cat_f1 = 2 * (cat_precision * cat_recall) / (cat_precision + cat_recall) if (cat_precision + cat_recall) > 0 else 0
            
            print(f"  {category}:")
            print(f"    TP: {cat_tp}, FP: {cat_fp}, FN: {cat_fn}")
            print(f"    Precision: {cat_precision:.4f}, Recall: {cat_recall:.4f}, F1: {cat_f1:.4f}")


def generate_contract_breakdown_report(contract_results, top_n=20):
    """
    Generate a detailed report of the performance breakdown by contract.
    
    Args:
        contract_results: Dictionary containing the analysis by contract
        top_n: Number of top contracts to include in the report
    """
    print("\n" + "="*80)
    print(" "*20 + "VULNERABILITY DETECTION PERFORMANCE BY CONTRACT")
    print("="*80)
    
    sorted_contracts = sorted(
        contract_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )
    
    gt_contracts = [(path, res) for path, res in sorted_contracts if res.get('ground_truth_category')]
    
    # Table header
    print("\n{:<50} {:<20} {:<8} {:<8} {:<8} {:<10}".format(
        "Contract", "Ground Truth", "TP", "FP", "FN", "F1 Score"))
    print("-"*110)
    
    for file_path, results in gt_contracts[:top_n]:
        short_path = extract_filename(file_path)
        
        print("{:<50} {:<20} {:<8} {:<8} {:<8} {:<10.4f}".format(
            short_path,
            results.get('ground_truth_category', 'N/A'),
            results['true_positives'],
            results['false_positives'],
            results.get('false_negatives', 0),
            results.get('f1_score', 0)
        ))
    
    if len(gt_contracts) > top_n:
        print(f"\n... and {len(gt_contracts) - top_n} more contracts with ground truth")
    
    print("\nSummary by Ground Truth Category:")
    
    category_stats = defaultdict(lambda: {
        'contracts': 0,
        'true_positives': 0,
        'false_positives': 0,
        'false_negatives': 0
    })
    
    for file_path, results in contract_results.items():
        category = results.get('ground_truth_category')
        if category:
            category_stats[category]['contracts'] += 1
            category_stats[category]['true_positives'] += results['true_positives']
            category_stats[category]['false_positives'] += results['false_positives']
            category_stats[category]['false_negatives'] += results.get('false_negatives', 0)
    
    print("\n{:<25} {:<10} {:<8} {:<8} {:<8} {:<10} {:<10} {:<10}".format(
        "Category", "Contracts", "TP", "FP", "FN", "Precision", "Recall", "F1 Score"))
    print("-"*95)
    
    for category, stats in sorted(category_stats.items()):
        tp = stats['true_positives']
        fp = stats['false_positives']
        fn = stats['false_negatives']
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("{:<25} {:<10} {:<8} {:<8} {:<8} {:<10.4f} {:<10.4f} {:<10.4f}".format(
            category,
            stats['contracts'],
            tp,
            fp,
            fn,
            precision,
            recall,
            f1
        ))


def visualize_tool_performance(tool_results, output_file='tool_performance.pdf'):
    """
    Create visualizations of tool performance metrics.
    
    Args:
        tool_results: Dictionary containing the analysis by tool
        output_file: Path to save the visualization
    """
    # Create dataframe from tool results
    tools = []
    precisions = []
    recalls = []
    f1_scores = []
    
    # Sort tools by F1 score
    sorted_tools = sorted(
        tool_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )
    
    for tool, results in sorted_tools:
        tools.append(tool)
        precisions.append(results.get('precision', 0))
        recalls.append(results.get('recall', 0))
        f1_scores.append(results.get('f1_score', 0))
    
    # Create figure
    plt.figure(figsize=(12, 8))
    
    # Bar chart for precision, recall, F1 score
    x = np.arange(len(tools))
    width = 0.25
    
    plt.bar(x - width, precisions, width, label='Precision', color='blue', alpha=0.7)
    plt.bar(x, recalls, width, label='Recall', color='green', alpha=0.7)
    plt.bar(x + width, f1_scores, width, label='F1 Score', color='red', alpha=0.7)
    
    plt.xlabel('Tools')
    plt.ylabel('Score')
    plt.title('Tool Performance Comparison')
    plt.xticks(x, tools, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.ylim(0, 1)
    
    for i, v in enumerate(precisions):
        plt.text(i - width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    for i, v in enumerate(recalls):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    for i, v in enumerate(f1_scores):
        plt.text(i + width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')


def visualize_category_performance(tool_results, contract_results, output_file='category_performance.pdf'):
    """
    Create visualizations of performance by vulnerability category.
    
    Args:
        tool_results: Dictionary containing the analysis by tool
        contract_results: Dictionary containing the analysis by contract
        output_file: Path to save the visualization
    """
    category_stats = defaultdict(lambda: {
        'contracts': 0,
        'true_positives': 0,
        'false_positives': 0,
        'false_negatives': 0
    })
    
    for file_path, results in contract_results.items():
        category = results.get('ground_truth_category')
        if category:
            category_stats[category]['contracts'] += 1
            category_stats[category]['true_positives'] += results['true_positives']
            category_stats[category]['false_positives'] += results['false_positives']
            category_stats[category]['false_negatives'] += results.get('false_negatives', 0)
    
    categories = []
    precisions = []
    recalls = []
    f1_scores = []
    
    for category, stats in sorted(category_stats.items()):
        tp = stats['true_positives']
        fp = stats['false_positives']
        fn = stats['false_negatives']
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        categories.append(category)
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)
    
    plt.figure(figsize=(14, 10))
    
    x = np.arange(len(categories))
    width = 0.25
    
    plt.bar(x - width, precisions, width, label='Precision', color='blue', alpha=0.7)
    plt.bar(x, recalls, width, label='Recall', color='green', alpha=0.7)
    plt.bar(x + width, f1_scores, width, label='F1 Score', color='red', alpha=0.7)
    
    plt.xlabel('Vulnerability Categories')
    plt.ylabel('Score')
    plt.title('Performance by Vulnerability Category')
    plt.xticks(x, categories, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.ylim(0, 1)
    
    for i, v in enumerate(precisions):
        plt.text(i - width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    for i, v in enumerate(recalls):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    for i, v in enumerate(f1_scores):
        plt.text(i + width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')


def main():
    ground_truth_file = 'sb_vulnerabilities_dasp.csv'
    
    output_files = [
        'output_access_control.csv',
        'output_arithmetic.csv',
        'output_bad_randomness.csv',
        'output_denial_of_service.csv',
        'output_front_running.csv',
        'output_other.csv',
        'output_reentrancy.csv',
        'output_short_addresses.csv',
        'output_time_manipulation.csv',
        'output_unchecked_low_level_calls.csv'
    ]
    
    existing_files = [f for f in output_files if os.path.isfile(f)]
    
    if not existing_files:
        print("Error: No output files found")
        return
    
    print(f"Analyzing {len(existing_files)} output files...")
    
    ground_truth_data = load_ground_truth(ground_truth_file)
    print(f"Loaded {len(ground_truth_data)} entries from ground truth")
    
    tool_results = analyze_by_tool(existing_files, ground_truth_data)
    print(f"Analyzed performance for {len(tool_results)} tools")
    
    contract_results = analyze_by_contract(existing_files, ground_truth_data)
    print(f"Analyzed performance for {len(contract_results)} contracts")
    
    tool_results, contract_results = calculate_false_negatives(tool_results, contract_results, ground_truth_data)
    
    generate_tool_breakdown_report(tool_results)
    generate_contract_breakdown_report(contract_results)
    
    visualize_tool_performance(tool_results)
    visualize_category_performance(tool_results, contract_results)
    
    print("\nAnalysis complete. Visualizations saved to:")
    print("- tool_performance.pdf")
    print("- category_performance.pdf")


if __name__ == "__main__":
    main()
