import os
import json
import argparse
import lightgbm as lgb
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief

patch_lief()
import ember

def get_confidence_level(score, threshold):
    """Determine confidence level based on score distance from threshold"""
    margin = abs(score - threshold)
    if score >= threshold:  # Malware prediction
        if margin >= 0.3:
            return "HIGH", "Strong malware indicators detected"
        elif margin >= 0.1:
            return "MEDIUM", "Moderate malware indicators detected"
        else:
            return "LOW", "Weak malware indicators detected - review recommended"
    else:  # Benign prediction
        if margin >= 0.3:
            return "HIGH", "Strongly appears benign"
        elif margin >= 0.1:
            return "MEDIUM", "Moderately appears benign"
        else:
            return "LOW", "Near threshold - manual review recommended"
def predict_file(booster, path):
    with open(path, 'rb') as f:
        data = f.read()
    score = ember.predict_sample(booster, data)
    return float(score)

def main():
    parser = argparse.ArgumentParser(description='Predict malware probability for a file')
    parser.add_argument('--model', help='Path to LightGBM model file')
    parser.add_argument('--file', help='Path to file to analyze')
    parser.add_argument('--threshold', type=float, help='Classification threshold (auto-loaded if not specified)')
    parser.add_argument('--verbose', action='store_true', help='Show detailed prediction information')
    args = parser.parse_args()
    
    BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    DEFAULT_MODEL = os.path.join(BASE, 'models', 'ember_lgbm.txt')
    # DEFAULT_SAMPLE = os.path.join(BASE, '85e229c6e469d9092e4241f9a56c3d3dec8a5da443caf4727f5bfceb14f1e3c8')
    DEFAULT_SAMPLE = os.path.join(BASE, 'fc457d54e133425d72fcfb6c71ec2dff181f0d7ea8c2c2011738a7d696b2500f')
    DEFAULT_METRICS = os.path.join(BASE, 'models', 'ember_lgbm_metrics.json')

    model_file = args.model or DEFAULT_MODEL
    target_file = args.file or DEFAULT_SAMPLE
    
    # Load optimal threshold from metrics file
    threshold = args.threshold
    if threshold is None:
        try:
            with open(DEFAULT_METRICS, 'r') as f:
                metrics = json.load(f)
                threshold = metrics.get('used_threshold', 0.5)
                print(f"Loaded optimal threshold: {threshold:.4f}")
        except FileNotFoundError:
            print("Warning: Metrics file not found, using default threshold 0.5")
            threshold = 0.5
    
    # Load the LightGBM model 
    booster = lgb.Booster(model_file=model_file)
    score = predict_file(booster, target_file)
    label = int(score >= threshold)
    confidence, explanation = get_confidence_level(score, threshold)
    
    print(f"\n=== MALWARE DETECTION RESULTS ===")
    print(f"File: {target_file}")
    print(f"Score: {score:.4f}")
    print(f"Threshold: {threshold:.4f}")
    print(f"Predicted label: {'MALWARE' if label else 'BENIGN'}")
    print(f"Confidence: {confidence}")
    print(f"Explanation: {explanation}")
    
    if args.verbose:
        print(f"\n=== VERBOSE DETAILS ===")
        print(f"Score distance from threshold: {abs(score - threshold):.4f}")
        try:
            with open(DEFAULT_METRICS, 'r') as f:
                metrics = json.load(f)
                print(f"Model AUC: {metrics.get('auc', 'N/A'):.4f}")
                print(f"Model Recall: {metrics.get('recall', 'N/A'):.4f}")
                print(f"Model Precision: {metrics.get('precision', 'N/A'):.4f}")
                print(f"False Negative Rate: {metrics.get('false_negative_rate', 'N/A'):.4f}")
        except FileNotFoundError:
            pass

if __name__ == '__main__':
    main()