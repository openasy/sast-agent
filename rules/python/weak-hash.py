import hashlib


def digest(password, blob):
    # ruleid: openasy.python.weak-hash
    a = hashlib.md5(password.encode()).hexdigest()
    # ruleid: openasy.python.weak-hash
    b = hashlib.sha1(password.encode()).hexdigest()
    # ok: openasy.python.weak-hash
    c = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    # ok: openasy.python.weak-hash
    d = hashlib.sha256(blob).hexdigest()
    return a, b, c, d
