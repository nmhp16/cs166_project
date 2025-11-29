"""Flask web application for malware detection."""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from compat_lief import patch_lief
patch_lief()

from flask import Flask, request, render_template, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

from detector import MalwareDetector
from config import MAX_FILE_SIZE

# Initialize app
app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'static'))

app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Lazy load detector
_detector = None

def get_detector():
    global _detector
    if _detector is None:
        _detector = MalwareDetector()
    return _detector


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))
    
    try:
        data = file.read()
        result = get_detector().analyze(data=data)
        result['filename'] = secure_filename(file.filename)
        result['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return render_template('result.html', result=result)
    except Exception as e:
        return render_template('error.html', error=str(e))


@app.route('/api/scan', methods=['POST'])
def api_scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    try:
        data = file.read()
        result = get_detector().analyze(data=data)
        result['filename'] = secure_filename(file.filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def file_too_large(e):
    return render_template('error.html', error='File too large (max 100 MB)'), 413


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    
    print(f"\nMalware Scanner running at http://127.0.0.1:{args.port}\n")
    app.run(host='127.0.0.1', port=args.port, debug=args.debug)
