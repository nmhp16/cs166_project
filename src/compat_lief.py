def patch_lief():
    try:
        import lief
    except Exception:
        return

    fallback = Exception
    names = [
        'bad_format',
        'bad_file',
        'pe_error',
        'parser_error',
        'read_out_of_bound'
    ]
    for n in names:
        if not hasattr(lief, n):
            try:
                setattr(lief, n, fallback)
            except Exception:
                # ignore failures to set attributes
                pass
    try:
        import numpy as np
        if not hasattr(np, 'int'):
            np.int = int
        if not hasattr(np, 'float'):
            np.float = float
    except Exception:
        # If numpy not available, nothing to patch
        pass


if __name__ == '__main__':
    patch_lief()
