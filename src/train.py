import argparse
import os
import json
import time
import ember
import lightgbm as lgb
from sklearn.metrics import roc_auc_score, accuracy_score, precision_recall_fscore_support
import joblib

EMBER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../ember2018'))
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/ember_lgbm.txt'))

if __name__ == "__main__":
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    print("Loading vectorized EMBER features (this may use a lot of RAM)...")

    X_train, y_train, X_test, y_test = ember.read_vectorized_features(EMBER_PATH)

    print(f"Training LightGBM model on {X_train.shape[0]} samples...")
    dtrain = lgb.Dataset(X_train, label=y_train)
    dtest = lgb.Dataset(X_test, label=y_test, reference=dtrain)

    params = {
        'objective': 'binary',
        'metric': 'auc',
        'verbosity': -1,
        'boosting_type': 'gbdt',
        'num_leaves': 64,
        'learning_rate': 0.1,
    }

    start = time.time()
    booster = lgb.train(params, dtrain, num_boost_round=100)
    
    duration = time.time() - start
    print(f"Training finished in {duration:.1f}s")

    # Save model
    print(f"Saving LightGBM model to {MODEL_PATH}")
    booster.save_model(MODEL_PATH)

    model_wrap = {'model_file': MODEL_PATH}
    joblib.dump(model_wrap, MODEL_PATH + '.joblib')

    # Evaluate on the test set
    probs = booster.predict(X_test)
    preds = (probs >= 0.5).astype(int)
    auc = roc_auc_score(y_test, probs)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary')

    metrics = {'auc': float(auc), 'accuracy': float(acc), 'precision': float(prec), 'recall': float(rec), 'f1': float(f1)}
    metfile = os.path.splitext(MODEL_PATH)[0] + '_metrics.json'
    with open(metfile, 'w') as f:
        json.dump(metrics, f, indent=2)

    print("Metrics:", metrics)
    print("Model and metrics saved.")