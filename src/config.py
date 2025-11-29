"""Configuration."""

import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
MODEL_PATH = os.path.join(MODELS_DIR, 'ember_lgbm.txt')
METRICS_PATH = os.path.join(MODELS_DIR, 'ember_lgbm_metrics.json')
EMBER_PATH = os.path.join(BASE_DIR, 'ember2018')

DEFAULT_THRESHOLD = 0.5
MAX_FILE_SIZE = 100 * 1024 * 1024

SUSPICIOUS_COMPANIES = [
    'lavasoft', 'webcompanion', 'mindspark', 'ask.com', 'conduit',
    'babylon', 'softonic', 'installcore', 'opencandy', 'sweetpacks',
    'somoto', 'perion', 'amonetize', 'installiq', 'outbrowse',
    'crossrider', 'superfish', 'wajam', 'spigot', 'yontoo',
]

SUSPICIOUS_PRODUCTS = [
    'webcompanion', 'browser protect', 'search protect', 'toolbar',
    'pc optimizer', 'driver updater', 'registry cleaner', 'speedup',
]

PACKER_SIGNATURES = {
    b'UPX': 'UPX',
    b'ASPack': 'ASPack',
    b'Themida': 'Themida',
    b'VMProtect': 'VMProtect',
    b'ConfuserEx': 'ConfuserEx',
    b'.NET Reactor': '.NET Reactor',
}
