import argparse
import os
import json
import time
import sys
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, accuracy_score, precision_recall_fscore_support, precision_recall_curve
sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief
patch_lief()
import ember
import lightgbm as lgb
import joblib

EMBER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../ember2018'))
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/ember_lgbm.txt'))

if __name__ == "__main__":
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    print("Loading vectorized EMBER features (this may use a lot of RAM)...")

    X_train, y_train, X_test, y_test = ember.read_vectorized_features(EMBER_PATH)

    print(f"Training LightGBM model on {X_train.shape[0]} samples...")
    
    # Split training data for validation and early stopping
    X_train_split, X_val_split, y_train_split, y_val_split = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )
    
    dtrain = lgb.Dataset(X_train_split, label=y_train_split)
    dval = lgb.Dataset(X_val_split, label=y_val_split, reference=dtrain)
    dtest = lgb.Dataset(X_test, label=y_test, reference=dtrain)
    
    # Calculate class imbalance weight
    neg_count = np.sum(y_train_split == 0)
    pos_count = np.sum(y_train_split == 1)
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
    print(f"Class distribution: {neg_count} benign, {pos_count} malware")
    print(f"Scale pos weight: {scale_pos_weight:.3f}")

    params = {
        'objective': 'binary',
        'metric': 'auc',
        'verbosity': -1,
        'boosting_type': 'gbdt',
        'num_leaves': 128,
        'learning_rate': 0.05,
        'max_depth': 10,
        'min_child_samples': 10,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'scale_pos_weight': scale_pos_weight,
        'random_state': 42,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1
    }

    start = time.time()
    booster = lgb.train(
        params, 
        dtrain, 
        num_boost_round=1000,
        valid_sets=[dval],
        callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=True)]
    )
    
    duration = time.time() - start
    print(f"Training finished in {duration:.1f}s")

    # Save model
    print(f"Saving LightGBM model to {MODEL_PATH}")
    booster.save_model(MODEL_PATH)

    model_wrap = {'model_file': MODEL_PATH}
    joblib.dump(model_wrap, MODEL_PATH + '.joblib')

    # Evaluate on the test set
    probs = booster.predict(X_test)
    
    # Find optimal threshold using precision-recall curve
    precisions, recalls, thresholds = precision_recall_curve(y_test, probs)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
    optimal_idx = np.argmax(f1_scores)
    optimal_threshold = thresholds[optimal_idx]
    
    # For malware detection, prioritize recall (catch more malware)
    # Use a threshold that gives at least 95% recall
    high_recall_threshold = None
    for i, (thresh, recall) in enumerate(zip(thresholds, recalls[:-1])):
        if recall >= 0.95:
            high_recall_threshold = thresh
            break
    
    # Use the more conservative threshold (higher recall)
    final_threshold = high_recall_threshold if high_recall_threshold is not None else optimal_threshold
    
    print(f"Optimal threshold (max F1): {optimal_threshold:.4f}")
    if high_recall_threshold is not None:
        print(f"High recall threshold (95%+ recall): {high_recall_threshold:.4f}")
    else:
        print("High recall threshold (95%+ recall): N/A")
    print(f"Using threshold: {final_threshold:.4f}")
    
    preds = (probs >= final_threshold).astype(int)
    auc = roc_auc_score(y_test, probs)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary')
    
    # Calculate false negative rate (critical for malware detection)
    fn_mask = (y_test == 1) & (preds == 0)
    false_negative_rate = np.sum(fn_mask) / np.sum(y_test == 1) if np.sum(y_test == 1) > 0 else 0
    
    # Feature importance
    feature_importance = booster.feature_importance(importance_type='gain')
    top_features = np.argsort(feature_importance)[-10:][::-1]

    metrics = {
        'auc': float(auc), 
        'accuracy': float(acc), 
        'precision': float(prec), 
        'recall': float(rec), 
        'f1': float(f1),
        'false_negative_rate': float(false_negative_rate),
        'optimal_threshold': float(optimal_threshold),
        'high_recall_threshold': float(high_recall_threshold) if high_recall_threshold is not None else None,
        'used_threshold': float(final_threshold),
        'best_iteration': booster.best_iteration,
        'num_features': len(feature_importance),
        'top_feature_indices': top_features.tolist(),
        'top_feature_importance': feature_importance[top_features].tolist()
    }
    metfile = os.path.splitext(MODEL_PATH)[0] + '_metrics.json'
    with open(metfile, 'w') as f:
        json.dump(metrics, f, indent=2)

    print("Metrics:", metrics)
    print("Model and metrics saved.")