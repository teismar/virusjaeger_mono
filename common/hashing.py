import hashlib
from typing import Tuple

BUF_SIZE = 1024 * 1024

def compute_hashes(f) -> Tuple[str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
