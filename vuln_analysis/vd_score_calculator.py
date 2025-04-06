import numpy as np
from sklearn.metrics import confusion_matrix
import os
import sys

def calculate_vd_score(y_true, y_pred_prob, tolerance=0.005):
    """
    Calculate the Vulnerability Detection Score (VD-S) as defined in
    "Vulnerability Detection with Code Language Models: How Far Are We?" paper.
    
    VD-S measures the False Negative Rate (FNR) under a constraint that
    the False Positive Rate (FPR) is below a specified tolerance level.
    
    Args:
        y_true (array-like): Ground truth labels (0 for benign, 1 for vulnerable)
        y_pred_prob (array-like): Predicted probabilities of being vulnerable
        tolerance (float): Maximum acceptable FPR, default is 0.5% (0.005)
        
    Returns:
        dict: A dictionary containing:
            - vd_score: The FNR at the specified FPR tolerance
            - threshold: The probability threshold used
            - fnr: The False Negative Rate
            - fpr: The False Positive Rate
            - tn: True Negatives
            - fp: False Positives
            - fn: False Negatives
            - tp: True Positives
    """
    # Ensure inputs are numpy arrays
    y_true = np.array(y_true)
    y_pred_prob = np.array(y_pred_prob)
    
    # Get sorted unique probability values to try as thresholds
    thresholds = np.unique(y_pred_prob)
    thresholds = np.sort(thresholds)[::-1]  # Sort in descending order
    
    # If there are too many thresholds, sample them to reduce computation
    if len(thresholds) > 1000:
        thresholds = np.percentile(y_pred_prob, np.linspace(0, 100, 1000))
    
    # Add 1.0 and 0.0 to ensure we cover the entire range
    thresholds = np.append(thresholds, [1.0, 0.0])
    thresholds = np.unique(thresholds)
    thresholds = np.sort(thresholds)[::-1]  # Sort in descending order
    
    best_threshold = None
    best_fnr = 1.0
    best_fpr = 0.0
    best_cm = None
    
    for threshold in thresholds:
        # Convert probabilities to binary predictions based on threshold
        y_pred = (y_pred_prob >= threshold).astype(int)
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 1
        
        # Check if FPR is below tolerance
        if fpr <= tolerance:
            # If multiple thresholds have FPR below tolerance, choose the one with lowest FNR
            if fnr < best_fnr or (fnr == best_fnr and fpr > best_fpr):
                best_threshold = threshold
                best_fnr = fnr
                best_fpr = fpr
                best_cm = (tn, fp, fn, tp)
    
    # If no threshold satisfies the FPR constraint, use the threshold with lowest FPR
    if best_threshold is None:
        for threshold in thresholds:
            y_pred = (y_pred_prob >= threshold).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 1
            
            if best_threshold is None or fpr < best_fpr:
                best_threshold = threshold
                best_fnr = fnr
                best_fpr = fpr
                best_cm = (tn, fp, fn, tp)
    
    tn, fp, fn, tp = best_cm
    
    return {
        'vd_score': best_fnr,
        'threshold': best_threshold,
        'fnr': best_fnr,
        'fpr': best_fpr,
        'tn': tn,
        'fp': fp,
        'fn': fn,
        'tp': tp
    }

if __name__ == "__main__":
    # demo execution for the vds calculation
    y_true = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]  # 5 benign, 5 vulnerable
    y_pred_prob = [0.1, 0.3, 0.4, 0.6, 0.7, 0.2, 0.5, 0.6, 0.8, 0.9]  # Predicted probabilities
    
    # calculate VD-S with default tolerance of 0.5%
    result = calculate_vd_score(y_true, y_pred_prob)
    
    print(f"VD-Score (FNR @ FPR ≤ 0.5%): {result['vd_score']:.4f}")
    print(f"Threshold: {result['threshold']:.4f}")
    print(f"FNR: {result['fnr']:.4f}")
    print(f"FPR: {result['fpr']:.4f}")
    print(f"Confusion Matrix:")
    print(f"TN: {result['tn']}, FP: {result['fp']}")
    print(f"FN: {result['fn']}, TP: {result['tp']}")
