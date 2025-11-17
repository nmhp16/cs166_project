

import ember
import os
import json

EMBER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../ember2018'))

def concatenate_jsonl_files(parts, output_file):
    print(f"Concatenating {len(parts)} files into {output_file}...")
    with open(output_file, 'w') as outfile:
        for fname in parts:
            fpath = os.path.join(EMBER_PATH, fname)
            if os.path.exists(fpath):
                with open(fpath, 'r') as infile:
                    for line in infile:
                        outfile.write(line)
            else:
                print(f"Warning: {fname} not found.")

if __name__ == "__main__":
    train_features_parts = [f"train_features_{i}.jsonl" for i in range(6)]
    train_features_out = os.path.join(EMBER_PATH, "train_features.jsonl")
    if not os.path.exists(train_features_out):
        concatenate_jsonl_files(train_features_parts, train_features_out)
        print("train_features.jsonl created.")
    else:
        print("train_features.jsonl already exists.")

    print(f"Processing EMBER dataset at: {EMBER_PATH}")
    ember.create_vectorized_features(EMBER_PATH)
    print("Feature extraction complete.")
