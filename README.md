# AI Malware Detection

**CS-166 Information Security | Team 13**

## Project Information

- **Department:** Department of Computer Science
- **Instructor:** Chao-Li Tarng
- **Team Members:** Ryan Tran, Nguyen Pham, Arnav Doshi

## Overview

Malware is one of the most persistent and costly threats in cybersecurity today. Traditional defenses against these attacks rely on signatures or outdated rules, which lag behind modern attacks and malware. According to Cybersecurity Ventures, "Ransomware will cost its victims around $265 billion USD annually by 2031, up from $42 billion in 2024, and $20 billion in 2021". This is a massive cost that will only continue to skyrocket as defenders face delayed detection, high false-negative rates, and growing issues in malware detection.

## Objective and Scope

We will develop a machine learning classifier in order to detect malicious activity by classifying samples based on observable features. To do this, we can use publicly available datasets to identify more complex patterns such as file metadata, code characteristics, API call behavior, and possible network activity. Our objective is to create a classifier tool to detect malware from executable files using machine learning. We plan to assign metrics (accuracy, precision, recall) to evaluate its performance and reliability.

## Approaches

1. **Data Collection** - Gather samples from VirusShare and the EMBER dataset. Verify data, remove duplicates, and create train/val/test splits
2. **Feature Extraction** - Use Python with pefile, Pandas, and NumPy to parse PE metadata, byte/section stats, and other patterns. Store features in simple tables
3. **Model Training** - Train baselines with Scikit-learn (e.g., logistic regression, tree ensembles) and possibly lightweight PyTorch models. Select useful models via cross-validation and evaluate with ROC/AUC and accuracy
4. **Implementation** - Create a program that ingests a file from the user and outputs a label + confidence. Minimal GUI possibly for demo

## Deliverables

- **Cleaned/curated dataset** - Cleaned, unduplicated, data samples with documented sources, splits, statistics. This gives us a reliable training/evaluation set
- **Feature set** - Identify key patterns and common behaviors between malware
- **Train models** - Train simple baselines based on cleaned training data. Get a strong ROC/AUC score and strong accuracy
- **Create detector** - Create CLI/simple GUI that scores inputs and gives a confidence score on the probability of malware. This will be our working demo
- **Release** - Create repo with README, env file, and cleaned code. This will be our final submission

## Project Structure


## Installation
```
# Download EMBER dataset
https://ember.elastic.co/ember_dataset_2018_2.tar.bz2

# Create python environment
python -m venv venv
source venv/bin/activate

# Install EMBER & dependencies
pip install git+https://github.com/elastic/ember.git
cd src & pip install -r requirements.txt

# Patch EMBER features.py
python patch_ember.py

# Process EMBER dataset 
python process_ember.py
```

## Usage

```
# Download infected file from VirusShare

# Run web app
python src/app.py

# Train model
python src/train.py

# CLI scan
python src/detector.py path/to/file.exe
```

## Performance Metrics

- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC

## References

- [Cybercrime Cost Statistics](https://www.esentire.com/web-native-pages/cybercrime-to-cost-the-world-9-5-trillion-usd-annually-in-2024)
- [VirusShare](https://virusshare.com/)
- [EMBER Dataset](https://github.com/elastic/ember)
