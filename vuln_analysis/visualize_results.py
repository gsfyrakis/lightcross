#!/usr/bin/env python3
"""
Script to visualize Smart Contract Vulnerability Analysis Results
"""
import pandas as pd
import numpy as np
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def plot_metrics(results_file='vulnerability_metrics_results.csv', output_dir='plots'):
    """
    Generate plots from vulnerability metrics results
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Load the results
    df = pd.read_csv(results_file)
    
    # Remove 'Overall' row for category-specific plots
    category_df = df[df['Category'] != 'Overall'].copy()
    category_df = category_df.sort_values(by='True Positives', ascending=False)
    categories = category_df['Category'].tolist()
    
    # 1. True Positives, False Positives, and False Negatives by category
    plt.figure(figsize=(14, 8))
    x = np.arange(len(categories))
    width = 0.25
    
    plt.bar(x - width, category_df['True Positives'], width, label='True Positives', color='green')
    plt.bar(x, category_df['False Positives'], width, label='False Positives', color='red')
    plt.bar(x + width, category_df['False Negatives'], width, label='False Negatives', color='orange')
    
    plt.xlabel('Vulnerability Category')
    plt.ylabel('Count')
    plt.title('Vulnerability Detection Performance by Category')
    plt.xticks(x, categories, rotation=45, ha='right')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vulnerability_counts.png'), dpi=300)
    
    # 2. Precision and Recall by category
    plt.figure(figsize=(14, 8))
    x = np.arange(len(categories))
    width = 0.35
    
    plt.bar(x - width/2, category_df['Precision'], width, label='Precision', color='blue')
    plt.bar(x + width/2, category_df['Recall'], width, label='Recall', color='purple')
    
    plt.xlabel('Vulnerability Category')
    plt.ylabel('Score')
    plt.title('Precision and Recall by Vulnerability Category')
    plt.xticks(x, categories, rotation=45, ha='right')
    plt.legend()
    plt.ylim(0, 1.0)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'precision_recall.png'), dpi=300)
    
    # 3. Overall metrics
    overall = df[df['Category'] == 'Overall'].iloc[0]
    metrics = ['True Positives', 'False Positives', 'False Negatives']
    values = [overall[metric] for metric in metrics]
    
    plt.figure(figsize=(10, 6))
    plt.bar(metrics, values, color=['green', 'red', 'orange'])
    plt.title('Overall Detection Performance')
    plt.ylabel('Count')
    for i, v in enumerate(values):
        plt.text(i, v + 5, str(int(v)), ha='center')
    plt.savefig(os.path.join(output_dir, 'overall_counts.png'), dpi=300)
    
    # 4. Overall precision and recall
    plt.figure(figsize=(8, 6))
    overall_metrics = ['Precision', 'Recall']
    overall_values = [overall[metric] for metric in overall_metrics]
    
    plt.bar(overall_metrics, overall_values, color=['blue', 'purple'])
    plt.title('Overall Precision and Recall')
    plt.ylim(0, 1.0)
    for i, v in enumerate(overall_values):
        plt.text(i, v + 0.05, f"{v:.4f}", ha='center')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.savefig(os.path.join(output_dir, 'overall_precision_recall.png'), dpi=300)
    
    print(f"Plots saved to {output_dir} directory")

if __name__ == "__main__":
    print("Generating visualization for vulnerability metrics...")
    plot_metrics()
    print("Visualization complete!")
