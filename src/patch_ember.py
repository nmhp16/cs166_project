import os

ember_features_path = os.path.join(
    os.path.dirname(__file__),
    '../venv/lib/python3.12/site-packages/ember/features.py'
)

# Read and patch the file
with open(ember_features_path, 'r') as f:
    lines = f.readlines()

with open(ember_features_path, 'w') as f:
    for line in lines:
        if 'FeatureHasher(50, input_type="string").transform([raw_obj[\'entry\']])' in line:
            # Patch the line
            line = line.replace(
                'FeatureHasher(50, input_type="string").transform([raw_obj[\'entry\']])',
                'FeatureHasher(50, input_type="string").transform([[raw_obj["entry"]]])'
            )
        f.write(line)

print("EMBER features.py patched for FeatureHasher compatibility.")