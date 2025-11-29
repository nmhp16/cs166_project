"""Train LightGBM model on EMBER dataset."""

import os
import sys
import json
import time
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_auc_score, accuracy_score, precision_recall_fscore_support,
    precision_recall_curve
)

sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief
patch_lief()

import ember
import lightgbm as lgb
from config import EMBER_PATH, MODELS_DIR, MODEL_PATH


def train_model():
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    print("Loading EMBER features...")
    X_train, y_train, X_test, y_test = ember.read_vectorized_features(EMBER_PATH)
    print(f"Raw training samples: {X_train.shape[0]:,}")
    print(f"Raw test samples: {X_test.shape[0]:,}")
    
    # Filter out unlabeled samples (y == -1)
    train_mask = y_train != -1
    test_mask = y_test != -1
    X_train, y_train = X_train[train_mask], y_train[train_mask]
    X_test, y_test = X_test[test_mask], y_test[test_mask]
    print(f"Labeled training: {X_train.shape[0]:,}, Labeled test: {X_test.shape[0]:,}")
    
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train
    )
    
    pos_count = int(np.sum(y_tr == 1))
    neg_count = int(np.sum(y_tr == 0))
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
    print(f"Class ratio: {neg_count:,} benign / {pos_count:,} malware")
    
    params = {
        'objective': 'binary',
        'metric': 'auc',
        'boosting_type': 'gbdt',
        'num_leaves': 256,
        'learning_rate': 0.05,
        'max_depth': 15,
        'min_child_samples': 20,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'scale_pos_weight': scale_pos_weight,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1,
        'random_state': 42,
        'verbosity': -1,
        'n_jobs': -1,
    }
    
    dtrain = lgb.Dataset(X_tr, label=y_tr)
    dval = lgb.Dataset(X_val, label=y_val, reference=dtrain)
    
    print("\nTraining...")
    start = time.time()
    
    model = lgb.train(
        params,
        dtrain,
        num_boost_round=1500,
        valid_sets=[dval],
        callbacks=[
            lgb.early_stopping(stopping_rounds=100, verbose=False),
            lgb.log_evaluation(period=100)
        ]
    )
    
    print(f"Training completed in {time.time() - start:.1f}s")
    print(f"Best iteration: {model.best_iteration}")
    
    probs = model.predict(X_test)
    auc = roc_auc_score(y_test, probs)
    
    precisions, recalls, thresholds = precision_recall_curve(y_test, probs)
    f1_scores = 2 * (precisions[:-1] * recalls[:-1]) / (precisions[:-1] + recalls[:-1] + 1e-8)
    
    best_f1_idx = np.argmax(f1_scores)
    optimal_thresh = float(thresholds[best_f1_idx])
    
    # Find threshold with 95%+ recall and 70%+ precision
    high_recall_thresh = None
    for i in range(len(thresholds) - 1, -1, -1):
        if recalls[i] >= 0.95 and precisions[i] >= 0.7:  # At least 70% precision
            high_recall_thresh = float(thresholds[i])
            break
    
    final_thresh = high_recall_thresh if (high_recall_thresh and high_recall_thresh > 0.1) else optimal_thresh
    
    if final_thresh < 0.1 or final_thresh > 0.9:
        final_thresh = 0.5  # Fallback to default
        print(f"Warning: Using default threshold 0.5 (computed was {optimal_thresh:.4f})")
    
    preds = (probs >= final_thresh).astype(int)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary')
    
    print(f"\n{'='*40}")
    print("EVALUATION RESULTS")
    print(f"{'='*40}")
    print(f"AUC:       {auc:.4f}")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"Threshold: {final_thresh:.4f}")
    
    model.save_model(MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")
    
    metrics = {
        'auc': float(auc),
        'accuracy': float(acc),
        'precision': float(prec),
        'recall': float(rec),
        'f1': float(f1),
        'used_threshold': float(final_thresh),
        'optimal_threshold': float(optimal_thresh),
        'best_iteration': model.best_iteration,
    }
    
    metrics_path = os.path.splitext(MODEL_PATH)[0] + '_metrics.json'
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {metrics_path}")


if __name__ == "__main__":
    train_model()
