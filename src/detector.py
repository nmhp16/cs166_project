"""Malware detection using EMBER features and LightGBM."""

import os
import sys
import json
import hashlib
import struct

import lightgbm as lgb

# Patch LIEF before importing ember
sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief
patch_lief()

import ember
from config import (
    MODEL_PATH, METRICS_PATH, DEFAULT_THRESHOLD,
    SUSPICIOUS_COMPANIES, SUSPICIOUS_PRODUCTS, PACKER_SIGNATURES
)


class MalwareDetector:
    
    def __init__(self, model_path=None, metrics_path=None):
        self.model_path = model_path or MODEL_PATH
        self.metrics_path = metrics_path or METRICS_PATH
        self.model = lgb.Booster(model_file=self.model_path)
        self.threshold = self._load_threshold()
    
    def _load_threshold(self):
        try:
            with open(self.metrics_path, 'r') as f:
                return json.load(f).get('used_threshold', DEFAULT_THRESHOLD)
        except FileNotFoundError:
            return DEFAULT_THRESHOLD
    
    def _get_ml_score(self, data):
        try:
            return float(ember.predict_sample(self.model, data))
        except Exception:
            return None
    
    def _compute_hashes(self, data):
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
    
    def _analyze_pe(self, data):
        info = {'is_pe': False, 'is_dotnet': False, 'is_packed': False, 'packer': None}
        
        if len(data) < 64 or data[:2] != b'MZ':
            return info
        
        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return info
            
            info['is_pe'] = True
            data_lower = data.lower()
            
            if b'mscoree.dll' in data_lower or b'_corexemain' in data_lower:
                info['is_dotnet'] = True
            
            for sig, name in PACKER_SIGNATURES.items():
                if sig in data:
                    info['is_packed'] = True
                    info['packer'] = name
                    break
        except Exception:
            pass
        
        return info
    
    def _check_pua_indicators(self, data):
        indicators = {'found': False, 'reasons': [], 'adjustment': 0.0}
        data_lower = data.lower()
        
        for company in SUSPICIOUS_COMPANIES:
            if company.encode() in data_lower:
                indicators['found'] = True
                indicators['reasons'].append(f'Suspicious vendor: {company}')
                indicators['adjustment'] += 0.2
                break
        
        for product in SUSPICIOUS_PRODUCTS:
            if product.encode() in data_lower:
                indicators['found'] = True
                indicators['reasons'].append(f'PUA pattern: {product}')
                indicators['adjustment'] += 0.15
                break
        
        for bundler in [b'installcore', b'opencandy', b'amonetize', b'somoto']:
            if bundler in data_lower:
                indicators['found'] = True
                indicators['reasons'].append('Bundler framework detected')
                indicators['adjustment'] += 0.2
                break
        
        indicators['adjustment'] = min(indicators['adjustment'], 0.6)
        return indicators
    
    def _get_verdict(self, score, pua_found):
        if score >= self.threshold:
            if pua_found:
                return 'PUA', 'Potentially Unwanted Application'
            return 'MALWARE', 'Malware Detected'
        elif score >= self.threshold * 0.8:
            return 'SUSPICIOUS', 'Suspicious - Review Recommended'
        return 'CLEAN', 'No Threats Detected'
    
    def _get_confidence(self, score):
        margin = abs(score - self.threshold)
        if margin >= 0.3:
            return 'High'
        elif margin >= 0.15:
            return 'Medium'
        return 'Low'
    
    def analyze(self, file_path=None, data=None):
        """Analyze file and return detection results."""
        if data is None:
            if file_path is None:
                raise ValueError("Provide file_path or data")
            with open(file_path, 'rb') as f:
                data = f.read()
        
        ml_score = self._get_ml_score(data)
        hashes = self._compute_hashes(data)
        pe_info = self._analyze_pe(data)
        pua = self._check_pua_indicators(data)
        
        base_score = ml_score if ml_score is not None else 0.5
        adjustment = pua['adjustment']
        if pe_info['is_dotnet'] and pua['found']:
            adjustment += 0.1
        if pe_info['is_packed']:
            adjustment += 0.05
            pua['reasons'].append(f"Packed: {pe_info['packer'] or 'Unknown'}")
        
        final_score = min(base_score + adjustment, 1.0)
        verdict_short, verdict = self._get_verdict(final_score, pua['found'])
        
        return {
            'file_size': len(data),
            'hashes': hashes,
            'ml_score': ml_score,
            'adjustment': adjustment,
            'final_score': final_score,
            'threshold': self.threshold,
            'verdict': verdict,
            'verdict_short': verdict_short,
            'confidence': self._get_confidence(final_score),
            'is_malicious': verdict_short in ['MALWARE', 'PUA', 'SUSPICIOUS'],
            'pe_info': pe_info,
            'reasons': pua['reasons'],
        }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Malware Detection Tool')
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--json', action='store_true', help='JSON output')
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    detector = MalwareDetector()
    result = detector.analyze(file_path=args.file)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*50}")
        print(f"File: {args.file}")
        print(f"Size: {result['file_size']:,} bytes")
        print(f"SHA256: {result['hashes']['sha256']}")
        print(f"{'='*50}")
        print(f"ML Score: {result['ml_score']:.4f}" if result['ml_score'] else "ML Score: N/A")
        print(f"Final Score: {result['final_score']:.4f}")
        print(f"Verdict: {result['verdict']} ({result['confidence']} confidence)")
        if result['reasons']:
            print(f"Reasons: {', '.join(result['reasons'])}")
        print(f"{'='*50}")


if __name__ == '__main__':
    main()
