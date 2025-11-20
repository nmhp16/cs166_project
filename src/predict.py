import os
import lightgbm as lgb
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief

patch_lief()
import ember

def predict_file(booster, path):
    with open(path, 'rb') as f:
        data = f.read()
    score = ember.predict_sample(booster, data)
    return float(score)

def main():
    BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    DEFAULT_MODEL = os.path.join(BASE, 'models', 'ember_lgbm.txt')
    DEFAULT_SAMPLE = os.path.join(BASE, '85e229c6e469d9092e4241f9a56c3d3dec8a5da443caf4727f5bfceb14f1e3c8')

    model_file = DEFAULT_MODEL
    target_file = DEFAULT_SAMPLE
    threshold = 0.5

    # Load the LightGBM model 
    booster = lgb.Booster(model_file=model_file)
    score = predict_file(booster, target_file)
    label = int(score >= threshold)
    print(f"File: {target_file}")
    print(f"Score: {score:.4f}")
    print(f"Predicted label (malware if >= {threshold}): {label}")

if __name__ == '__main__':
    main()