"""Compatibility patches for LIEF and numpy."""

def patch_lief():
    """Patch missing LIEF exception types and deprecated numpy aliases."""
    try:
        import lief
    except Exception:
        return

    for name in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound']:
        if not hasattr(lief, name):
            try:
                setattr(lief, name, Exception)
            except Exception:
                pass
    
    try:
        import numpy as np
        if not hasattr(np, 'int'):
            np.int = int
        if not hasattr(np, 'float'):
            np.float = float
    except Exception:
        pass
